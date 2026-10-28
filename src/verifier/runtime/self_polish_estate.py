"""Fail-closed candidate-estate census for Verifier Standard (VSTD).

Terminology: abstract syntax tree (AST); application programming interface (API);
command-line interface (CLI); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); identifier (ID).

The census binds Git-tracked working bytes, bounded nonignored untracked bytes,
and mechanically visible registries. It does not decide semantic applicability,
authenticate authority or evidence, execute a candidate command, load an
external plugin, or establish complete self-polish.
"""
from __future__ import annotations

import argparse
import ast
from fnmatch import fnmatch
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from typing import Any

import verifier as verifier_package
from verifier.core import namespace as core_namespace_module
from verifier.core.namespace import ObjectKind
from verifier.domains import catalog as domain_catalog_module
from verifier.domains.contracts import application_requirements
from verifier.interoperability import reference_catalog as reference_catalog_module
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.runtime import core_tier_progression, public_cli


ESTATE_SCHEMA = "verifier-self-polish-candidate-estate-3"
CANDIDATE_SOURCE_CENSUS_SCHEMA = (
    "verifier-self-polish-candidate-source-census-1"
)
APPLICABILITY_LEDGER_SCHEMA = "verifier-self-polish-applicability-ledger-1"
APPLICABILITY_RESULT_SCHEMA = "verifier-self-polish-applicability-result-1"
MAX_SOURCE_FILES = 20_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_IGNORED_PATHS = 100_000
MAX_CANDIDATES = 250_000
MAX_AST_BYTES = 8 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_LEDGER_BYTES = 128 * 1024 * 1024
MAX_CLI_DEPTH = 16
MAX_CLI_ROUTES = 16_384
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}\Z")
_RUNTIME_PROVIDER_MODULES = (
    verifier_package,
    core_namespace_module,
    domain_catalog_module,
    application_requirements,
    reference_catalog_module,
    core_tier_progression,
    public_cli,
)

REQUIRED_CATEGORIES = (
    "candidate_source_file",
    "package_file",
    "python_module",
    "python_function",
    "installed_cell",
    "installed_route",
    "installed_mechanism",
    "structural_family",
    "structural_membership",
    "structural_route_crosswalk",
    "non_route_gate",
    "public_cli_route",
    "public_cli_preparser_route",
    "console_alias",
    "public_lazy_export",
    "domain",
    "domain_check",
    "interoperability_component",
    "schema",
    "native_route",
    "compatibility_route",
    "package_data_candidate",
    "unresolved_surface",
)

CLAIM_BOUNDARY = (
    "Mechanical enumeration PASS means only that every declared estate category was "
    "enumerated from one unchanged candidate-source snapshot containing Git-tracked "
    "working bytes and bounded nonignored untracked ordinary files. Ignored cache/build "
    "artifact and generated local-analysis paths are classified and path-bound under an "
    "explicit exclusion taxonomy, "
    "but their bytes are not verified. Candidate presence, a "
    "caller-authored applicability PASS, a digest, importability, or parser reachability "
    "does not establish semantic applicability, authority, evidence sufficiency, complete "
    "repository/package closure, Tier 1 completion, polished status, or release authority."
)

IGNORED_EXCLUSION_TAXONOMY = {
    "schema_version": "verifier-self-polish-ignored-exclusion-taxonomy-2",
    "root_prefixes": [
        ".eggs/", ".hypothesis/", ".mypy_cache/", ".nox/",
        ".pytest_cache/", ".ruff_cache/", ".tox/", ".venv/", ".vstd-work/",
        "build/", "dist/", "htmlcov/", "node_modules/", "venv/",
    ],
    "directory_names": ["__pycache__"],
    "directory_suffixes": [".egg-info"],
    "root_files": [".coverage"],
    "boundary": (
        "Only ignored cache, environment, dependency, coverage, build-artifact, and "
        "root-local generated analysis-output paths match this taxonomy. Their path "
        "identities are bound; their bytes are excluded and remain unverified. Generated "
        "analysis output confers no evidence on the source census that excludes it."
    ),
}


class EstateError(ValueError):
    """Fixed census refusal code; submitted values are not reflected."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EstateError(code)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def value_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


IGNORED_EXCLUSION_TAXONOMY_DIGEST = value_digest(
    IGNORED_EXCLUSION_TAXONOMY
)


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


_GIT_PROCESS_ENVIRONMENT_KEYS = frozenset({
    # The executable is resolved from PATH before launch.  These remaining
    # variables are process/runtime plumbing, not Git repository selectors.
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "TMPDIR",
})


def _git_process_environment() -> dict[str, str]:
    """Build a closed observer environment without ambient Git authority.

    Git treats many ``GIT_*`` variables as command-line authority: they can
    redirect the repository, index, object store, worktree, configuration, or
    executable helpers.  Copying the caller environment would therefore let a
    verifier request about root A observe root B.  Start from a small process
    allowlist and add only fixed observer controls.
    """

    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in _GIT_PROCESS_ENVIRONMENT_KEYS
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        # Explicitly name the platform null device so Git never consults the
        # caller's user-level configuration, even when HOME is synthesized by
        # Git for Windows.
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LC_ALL": "C",
        "LANG": "C",
    })
    return environment


def _git_executable(environment: dict[str, str]) -> str:
    """Resolve one absolute Git executable or fail closed."""

    executable = shutil.which("git", path=environment.get("PATH"))
    if executable is None:
        raise EstateError("GIT_STATE_UNAVAILABLE")
    try:
        selected = Path(executable).resolve(strict=True)
    except OSError as exc:
        raise EstateError("GIT_STATE_UNAVAILABLE") from exc
    _require(selected.is_file() and selected.is_absolute(),
             "GIT_STATE_UNAVAILABLE")
    return str(selected)


def _run_git(root: Path, *arguments: str) -> bytes:
    try:
        selected_root = Path(root).resolve(strict=True)
    except (OSError, TypeError) as exc:
        raise EstateError("GIT_STATE_UNAVAILABLE") from exc
    _require(selected_root.is_dir(), "GIT_STATE_UNAVAILABLE")
    _require(
        bool(arguments) and all(type(argument) is str and argument for argument in arguments),
        "GIT_STATE_UNAVAILABLE",
    )
    environment = _git_process_environment()
    executable = _git_executable(environment)
    argv = [
        executable,
        "--no-optional-locks",
        # A repository-owned fsmonitor is executable code, not observation.
        # Disable it before every status/index query.  Also prevent untracked
        # cache policy inherited from local feature bundles from making the
        # observer depend on a mutable cached view.
        "-c", "core.fsmonitor=false",
        "-c", "core.untrackedCache=false",
        "-c", "feature.manyFiles=false",
        # System/global safe.directory policy is intentionally absent from the
        # closed environment.  The caller selected this exact root for bounded
        # observation, so preserve legitimate cross-volume Windows worktrees
        # with one request-local exception instead of ambient configuration.
        "-c", f"safe.directory={selected_root}",
        "-c", "core.longpaths=true",
        "-C", str(selected_root),
        *arguments,
    ]
    try:
        completed = subprocess.run(
            argv,
            cwd=selected_root,
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EstateError("GIT_STATE_UNAVAILABLE") from exc
    _require(completed.returncode == 0, "GIT_STATE_UNAVAILABLE")
    _require(len(completed.stdout) <= MAX_GIT_OUTPUT_BYTES,
             "GIT_OUTPUT_CAPACITY_EXHAUSTED")
    return completed.stdout


def _git_coordinate(root: Path) -> dict[str, str]:
    try:
        repository = _run_git(root, "config", "--get", "remote.origin.url").decode(
            "utf-8"
        ).strip()
        revision = _run_git(root, "rev-parse", "HEAD").decode("ascii").strip()
    except UnicodeError as exc:
        raise EstateError("GIT_COORDINATE_INVALID") from exc
    _require(bool(repository) and len(repository) <= 2048,
             "GIT_COORDINATE_INVALID")
    _require(_REVISION.fullmatch(revision) is not None,
             "GIT_COORDINATE_INVALID")
    return {"repository": repository, "revision": revision}


def _git_tracked_paths(root: Path, *, allow_empty: bool = False) -> tuple[str, ...]:
    raw = _run_git(root, "ls-files", "-z")
    try:
        paths = tuple(item for item in raw.decode("utf-8").split("\0") if item)
    except UnicodeError as exc:
        raise EstateError("TRACKED_PATH_INVALID") from exc
    _require((0 if allow_empty else 1) <= len(paths) <= MAX_SOURCE_FILES,
             "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED")
    _require(len(set(paths)) == len(paths), "CANDIDATE_SOURCE_PATH_DUPLICATED")
    _require(paths == tuple(sorted(paths)), "CANDIDATE_SOURCE_PATH_ORDER_DIFFERS")
    return paths


def _git_index_state(root: Path, tracked_paths: tuple[str, ...]) \
        -> tuple[dict[str, str], str]:
    """Bind canonical stage-zero ordinary-file modes from the Git index."""
    raw = _run_git(root, "ls-files", "--stage", "-z")
    try:
        records = tuple(
            item for item in raw.decode("utf-8").split("\0") if item
        )
    except UnicodeError as exc:
        raise EstateError("GIT_INDEX_INVALID") from exc
    modes: dict[str, str] = {}
    for record in records:
        try:
            header, path = record.split("\t", 1)
            mode, object_id, stage = header.split(" ")
        except ValueError as exc:
            raise EstateError("GIT_INDEX_INVALID") from exc
        _require(
            mode in {"100644", "100755"}
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id)
                is not None
            and stage == "0"
            and path not in modes,
            "GIT_INDEX_NOT_ORDINARY_STAGE_ZERO",
        )
        modes[path] = mode
    _require(
        tuple(sorted(modes)) == tracked_paths,
        "GIT_INDEX_TRACKED_SET_DIFFERS",
    )
    return modes, bytes_digest(raw)


def _git_status_digest(root: Path) -> str:
    raw = _run_git(
        root, "status", "--porcelain=v2", "-z", "--untracked-files=all"
    )
    return bytes_digest(raw)


def _git_untracked_paths(root: Path) -> tuple[str, ...]:
    """Return all nonignored untracked files visible to Git discovery."""
    raw = _run_git(root, "ls-files", "--others", "--exclude-standard", "-z")
    try:
        paths = tuple(item for item in raw.decode("utf-8").split("\0") if item)
    except UnicodeError as exc:
        raise EstateError("GIT_STATUS_INVALID") from exc
    _require(len(paths) <= MAX_SOURCE_FILES,
             "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED")
    _require(len(set(paths)) == len(paths), "CANDIDATE_SOURCE_PATH_DUPLICATED")
    _require(paths == tuple(sorted(paths)), "CANDIDATE_SOURCE_PATH_ORDER_DIFFERS")
    return paths


def _git_ignored_paths(root: Path) -> tuple[str, ...]:
    raw = _run_git(
        root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"
    )
    try:
        paths = tuple(item for item in raw.decode("utf-8").split("\0") if item)
    except UnicodeError as exc:
        raise EstateError("GIT_IGNORED_PATH_INVALID") from exc
    _require(len(paths) <= MAX_IGNORED_PATHS,
             "IGNORED_PATH_CAPACITY_EXHAUSTED")
    _require(len(set(paths)) == len(paths), "IGNORED_PATH_DUPLICATED")
    _require(paths == tuple(sorted(paths)), "IGNORED_PATH_ORDER_DIFFERS")
    return paths


def _ignored_exclusion_id(relative: str) -> str | None:
    folded = relative.casefold()
    for prefix in IGNORED_EXCLUSION_TAXONOMY["root_prefixes"]:
        if folded.startswith(prefix.casefold()):
            return "root-prefix:" + prefix
    parts = Path(relative).parts
    for part in parts:
        if part.casefold() in {
            value.casefold()
            for value in IGNORED_EXCLUSION_TAXONOMY["directory_names"]
        }:
            return "directory-name:" + part
        if any(part.casefold().endswith(suffix.casefold())
               for suffix in IGNORED_EXCLUSION_TAXONOMY[
                   "directory_suffixes"
               ]):
            return "directory-suffix:" + next(
                suffix for suffix in IGNORED_EXCLUSION_TAXONOMY[
                    "directory_suffixes"
                ] if part.casefold().endswith(suffix.casefold())
            )
    if folded in {
        value.casefold() for value in IGNORED_EXCLUSION_TAXONOMY["root_files"]
    }:
        return "root-file:" + relative
    return None


_IGNORED_DISCOVERABLE_EXTENSIONS = {
    ".bat", ".c", ".cc", ".cfg", ".cmd", ".cpp", ".dll", ".dylib",
    ".exe", ".h", ".hpp", ".ini", ".js", ".json", ".mjs", ".ps1",
    ".py", ".pyi", ".pyd", ".sh", ".so", ".toml", ".ts", ".tsx",
    ".yaml", ".yml",
}
_IGNORED_ROOT_CONTROL_FILES = {
    "agents.md", "manifest.in", "noxfile.py", "pyproject.toml", "pytest.ini",
    "setup.cfg", "setup.py", "time.md", "tox.ini",
}
_IGNORED_DISCOVERABLE_PREFIXES = (
    ".github/workflows/", "receipts/schema/", "scripts/", "src/", "tests/",
)


def _ignored_scan(paths: tuple[str, ...]) -> dict[str, Any]:
    excluded: list[dict[str, str]] = []
    inert: list[str] = []
    risky: list[str] = []
    for relative in paths:
        exclusion_id = _ignored_exclusion_id(relative)
        if exclusion_id is not None:
            excluded.append({"path": relative, "taxonomy_id": exclusion_id})
            continue
        folded = relative.casefold()
        suffix = Path(relative).suffix.casefold()
        extensionless_script = (
            folded.startswith("scripts/") and suffix == ""
        )
        discoverable = (
            suffix in _IGNORED_DISCOVERABLE_EXTENSIONS
            or folded in _IGNORED_ROOT_CONTROL_FILES
            or any(folded.startswith(prefix)
                   for prefix in _IGNORED_DISCOVERABLE_PREFIXES)
            or extensionless_script
        )
        (risky if discoverable else inert).append(relative)
    _require(not risky, "IGNORED_DISCOVERABLE_SOURCE_PRESENT")
    return {
        "ignored_path_count": len(paths),
        "ignored_path_set_digest": value_digest(list(paths)),
        "exclusion_taxonomy_digest": IGNORED_EXCLUSION_TAXONOMY_DIGEST,
        "excluded_cache_build_path_count": len(excluded),
        "excluded_cache_build_paths_digest": value_digest(excluded),
        "inert_ignored_path_count": len(inert),
        "inert_ignored_paths_digest": value_digest(inert),
        "excluded_bytes_status": "NOT_VERIFIED",
    }


def _resolve_source(root: Path, relative: str) -> Path:
    _require(type(relative) is str and relative and "\\" not in relative
             and not relative.startswith("/"),
             "CANDIDATE_SOURCE_PATH_INVALID")
    parts = Path(relative).parts
    _require(not Path(relative).is_absolute()
             and all(part not in ("", ".", "..") for part in parts),
             "CANDIDATE_SOURCE_PATH_INVALID")
    unresolved = root / Path(*parts)
    _require(not unresolved.is_symlink(),
             "CANDIDATE_SOURCE_NOT_REGULAR_FILE")
    try:
        metadata = unresolved.lstat()
    except OSError as exc:
        raise EstateError("CANDIDATE_SOURCE_NOT_REGULAR_FILE") from exc
    _require(stat.S_ISREG(metadata.st_mode),
             "CANDIDATE_SOURCE_NOT_REGULAR_FILE")
    attributes = getattr(metadata, "st_file_attributes", 0)
    _require(not (attributes & 0x400), "CANDIDATE_SOURCE_REPARSE_POINT")
    candidate = unresolved.resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EstateError("CANDIDATE_SOURCE_PATH_ESCAPES_ROOT") from exc
    _require(candidate.is_file(), "CANDIDATE_SOURCE_NOT_REGULAR_FILE")
    return candidate


def _candidate_source_census(root: Path, tracked_paths: tuple[str, ...],
                             untracked_paths: tuple[str, ...],
                             ignored_paths: tuple[str, ...], *,
                             tracked_modes: dict[str, str],
                             git_index_digest: str,
                             git_status_digest: str) -> dict[str, Any]:
    _require(
        tracked_paths == tuple(sorted(tracked_paths))
        and untracked_paths == tuple(sorted(untracked_paths))
        and ignored_paths == tuple(sorted(ignored_paths))
        and len(tracked_paths) == len(set(tracked_paths))
        and len(untracked_paths) == len(set(untracked_paths))
        and len(ignored_paths) == len(set(ignored_paths)),
        "CANDIDATE_SOURCE_PATH_SET_INVALID",
    )
    _require(not (set(tracked_paths) & set(untracked_paths)),
             "CANDIDATE_SOURCE_PROVENANCE_OVERLAP")
    _require(
        set(tracked_modes) == set(tracked_paths)
        and all(mode in {"100644", "100755"}
                for mode in tracked_modes.values()),
        "GIT_INDEX_TRACKED_SET_DIFFERS",
    )
    _require(
        _SHA256.fullmatch(git_index_digest) is not None
        and _SHA256.fullmatch(git_status_digest) is not None,
        "CANDIDATE_SOURCE_GIT_STATE_DIGEST_INVALID",
    )
    selected = sorted(
        [(path, "GIT_TRACKED") for path in tracked_paths]
        + [(path, "WORKTREE_UNTRACKED_NONIGNORED")
           for path in untracked_paths]
    )
    _require(0 < len(selected) <= MAX_SOURCE_FILES,
             "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED")
    ignored_scan = _ignored_scan(ignored_paths)
    files: list[dict[str, Any]] = []
    total = 0
    for relative, provenance in selected:
        path = _resolve_source(root, relative)
        size = path.stat().st_size
        _require(0 <= size <= MAX_FILE_BYTES,
                 "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED")
        total += size
        _require(total <= MAX_SOURCE_BYTES,
                 "CANDIDATE_SOURCE_BYTE_CAPACITY_EXHAUSTED")
        raw = path.read_bytes()
        _require(len(raw) == size, "CANDIDATE_SOURCE_MUTATED")
        files.append({
            "path": relative,
            "size": size,
            "sha256": bytes_digest(raw),
            "provenance": provenance,
            "git_mode": (
                tracked_modes[relative]
                if provenance == "GIT_TRACKED"
                else "UNTRACKED_REGULAR"
            ),
        })
    body = {
        "schema_version": CANDIDATE_SOURCE_CENSUS_SCHEMA,
        "file_count": len(files),
        "total_bytes": total,
        "provenance_counts": {
            "GIT_TRACKED": len(tracked_paths),
            "WORKTREE_UNTRACKED_NONIGNORED": len(untracked_paths),
        },
        "git_index_digest": git_index_digest,
        "git_status_digest": git_status_digest,
        "files": files,
        "ignored_scan": ignored_scan,
    }
    return {**body, "census_digest": value_digest(body)}


def capture_candidate_source_census(root: str | Path, *,
                                    allow_untracked_only: bool = False) -> dict[str, Any]:
    """Capture the exact v3 candidate-source selection or fail closed.

    This is the public selector shared by the estate and its downstream gates.
    It includes Git-tracked working bytes and every bounded nonignored untracked
    ordinary file, and it rejects discoverable ignored source/control entries.
    Ignored cache/build paths are path-bound under the fixed exclusion taxonomy;
    their bytes remain explicitly unverified.
    """

    selected = Path(root).resolve(strict=True)
    _require(selected.is_dir(), "REPOSITORY_ROOT_INVALID")
    # New repository admission may precede the first git add. Retained estate
    # profiles keep their original nonempty tracked-set contract by default.
    tracked = (_git_tracked_paths(selected, allow_empty=True) if allow_untracked_only
               else _git_tracked_paths(selected))
    tracked_modes, index_digest = _git_index_state(selected, tracked)
    return _candidate_source_census(
        selected, tracked, _git_untracked_paths(selected),
        _git_ignored_paths(selected), tracked_modes=tracked_modes,
        git_index_digest=index_digest,
        git_status_digest=_git_status_digest(selected),
    )


def _source_refs(snapshot: dict[str, Any], *paths: str) -> list[dict[str, str]]:
    selected = {row["path"]: row["sha256"] for row in snapshot["files"]}
    return [{"path": path, "sha256": selected[path]}
            for path in sorted(set(paths)) if path in selected]


def _runtime_source_binding(root: Path,
                            snapshot: dict[str, Any]) -> dict[str, Any]:
    """Prove imported Verifier providers equal the selected root's exact bytes.

    The estate enumerator deliberately uses installed Python objects from the
    finite provider tuple above for registries and the public parser. Their
    names are not a source binding:
    without this check a caller could select root A while Python resolves those
    objects from different bytes in root B or an installed wheel.  Bind every
    loaded ``verifier`` module to the corresponding selected source path and
    byte digest before any such object contributes a candidate.  An installed
    wheel is therefore admissible only when its executing module bytes exactly
    reproduce the selected repository bytes.
    """

    expected = {row["path"]: row["sha256"] for row in snapshot["files"]}
    bindings: list[dict[str, str]] = []
    for module in _RUNTIME_PROVIDER_MODULES:
        name = module.__name__
        origin = getattr(module, "__file__", None)
        _require(origin is not None, "RUNTIME_PROVIDER_SOURCE_INVALID")
        suffix = name.split(".")[1:]
        relative = "src/verifier" + ("/" + "/".join(suffix) if suffix else "")
        relative += "/__init__.py" if hasattr(module, "__path__") else ".py"
        _require(relative in expected, "RUNTIME_PROVIDER_SOURCE_UNTRACKED")
        try:
            runtime_source = Path(origin).resolve(strict=True)
            _require(runtime_source.is_file(), "RUNTIME_PROVIDER_SOURCE_INVALID")
            raw = runtime_source.read_bytes()
        except OSError as exc:
            raise EstateError("RUNTIME_PROVIDER_SOURCE_UNAVAILABLE") from exc
        _require(bytes_digest(raw) == expected[relative],
                 "RUNTIME_PROVIDER_SOURCE_BYTES_DIFFER")
        bindings.append({
            "module": name,
            "path": relative,
            "sha256": expected[relative],
        })
    return {
        "status": "PASS",
        "module_count": len(bindings),
        "bindings_digest": value_digest(bindings),
    }


def _candidate(category: str, candidate_type: str, candidate_id: str, *,
               source_refs: list[dict[str, str]], metadata: dict[str, Any]) -> dict[str, Any]:
    _require(category in REQUIRED_CATEGORIES, "ESTATE_CATEGORY_UNREGISTERED")
    _require(type(candidate_id) is str and 0 < len(candidate_id) <= 4096,
             "CANDIDATE_ID_INVALID")
    _require(len(canonical_bytes(metadata)) <= 64 * 1024,
             "CANDIDATE_METADATA_CAPACITY_EXHAUSTED")
    body = {
        "candidate_id": candidate_id,
        "category": category,
        "candidate_type": candidate_type,
        "source_refs": source_refs,
        "mechanical_status": "PASS",
        "applicability_status": "UNKNOWN",
        "authority_status": "NOT_ESTABLISHED",
        "evidence_status": "NOT_ESTABLISHED",
        "semantic_status": "NOT_ESTABLISHED",
        "metadata": metadata,
    }
    return {**body, "candidate_digest": value_digest(body)}


def _parse_python(root: Path, relative: str) -> ast.Module:
    raw = (root / relative).read_bytes()
    _require(len(raw) <= MAX_AST_BYTES, "PYTHON_SOURCE_CAPACITY_EXHAUSTED")
    try:
        return ast.parse(raw.decode("utf-8"), filename=relative)
    except (UnicodeError, SyntaxError) as exc:
        raise EstateError("PYTHON_SOURCE_INVALID") from exc


def _literal_assignment(tree: ast.Module, name: str) -> Any:
    matches = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                matches.append(node.value)
    _require(len(matches) == 1, "STATIC_REGISTRY_MISSING_OR_DUPLICATED")
    try:
        return ast.literal_eval(matches[0])
    except (ValueError, TypeError) as exc:
        raise EstateError("STATIC_REGISTRY_NOT_LITERAL") from exc


def _source_file_rows(root: Path,
                      snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in snapshot["files"]:
        refs = [{"path": item["path"], "sha256": item["sha256"]}]
        rows.append(_candidate(
            "candidate_source_file", "CANDIDATE_SOURCE_FILE",
            "candidate-source-file:" + item["path"],
            source_refs=refs,
            metadata={"size": item["size"],
                      "provenance": item["provenance"],
                      "git_mode": item["git_mode"]},
        ))
        if item["path"].startswith("src/verifier/"):
            rows.append(_candidate(
                "package_file", "PYTHON_PACKAGE_FILE", "package-file:" + item["path"],
                source_refs=refs, metadata={"size": item["size"]},
            ))
    return rows


def _python_rows(root: Path, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    python_paths = [item["path"] for item in snapshot["files"]
                    if item["path"].startswith("src/verifier/")
                    and item["path"].endswith(".py")]
    for relative in python_paths:
        module = relative[len("src/"):-3].replace("/", ".")
        refs = _source_refs(snapshot, relative)
        rows.append(_candidate(
            "python_module", "PYTHON_MODULE", "python-module:" + module,
            source_refs=refs, metadata={"module": module},
        ))
        tree = _parse_python(root, relative)
        callables: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef,
                              str, str]] = []

        class CallableVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.scope: list[tuple[str, str]] = []

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                self.scope.append(("class", node.name))
                self.generic_visit(node)
                self.scope.pop()

            def _visit_callable(
                self, node: ast.FunctionDef | ast.AsyncFunctionDef,
            ) -> None:
                pieces: list[str] = []
                for kind, name in self.scope:
                    pieces.append(name)
                    if kind == "function":
                        pieces.append("<locals>")
                pieces.append(node.name)
                qualname = ".".join(pieces)
                if not self.scope:
                    kind = "TOP_LEVEL_CANDIDATE_FUNCTION"
                elif self.scope[-1][0] == "class" \
                        and not any(item[0] == "function"
                                    for item in self.scope):
                    kind = "CLASS_METHOD_CANDIDATE_FUNCTION"
                else:
                    kind = "NESTED_CANDIDATE_FUNCTION"
                callables.append((node, qualname, kind))
                self.scope.append(("function", node.name))
                self.generic_visit(node)
                self.scope.pop()

            visit_FunctionDef = _visit_callable
            visit_AsyncFunctionDef = _visit_callable

        CallableVisitor().visit(tree)
        counts: dict[str, int] = {}
        for _, qualname, _ in callables:
            counts[qualname] = counts.get(qualname, 0) + 1
        for node, qualname, candidate_type in callables:
            identity = qualname if counts[qualname] == 1 \
                else f"{qualname}@{node.lineno}"
            rows.append(_candidate(
                "python_function", candidate_type,
                f"python-function:{module}:{identity}", source_refs=refs,
                metadata={"module": module, "symbol": node.name,
                          "qualname": qualname, "line": node.lineno,
                          "async": isinstance(node, ast.AsyncFunctionDef)},
            ))
    return rows


def _mechanism_source(mechanism: str, snapshot: dict[str, Any]) -> str | None:
    module, _ = mechanism.rsplit(".", 1)
    relative = "src/" + module.replace(".", "/") + ".py"
    tracked = {row["path"] for row in snapshot["files"]}
    return relative if relative in tracked else None


def _installed_route_rows(snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inventory = core_tier_progression.installed_core_route_inventory()
    _require(inventory.get("status") == "PASS"
             and inventory.get("family_cell_count") == 234
             and inventory.get("registered_route_membership_count") == 408,
             "INSTALLED_ROUTE_INVENTORY_INVALID")
    rows = []
    mechanisms: dict[str, str | None] = {}
    for cell in inventory["family_cells"]:
        kind, tier = cell["object_kind"], cell["tier"]
        rows.append(_candidate(
            "installed_cell", "INSTALLED_OBJECT_TIER_CELL",
            f"installed-cell:{kind}:{tier}",
            source_refs=_source_refs(snapshot, "src/verifier/domains/inventory.py"),
            metadata={"object_kind": kind, "tier": tier,
                      "tier_name": cell["tier_name"],
                      "membership_count": cell["registered_route_membership_count"]},
        ))
        for member in cell["registered_route_memberships"]:
            mechanism = member["checking_mechanism"]
            source = _mechanism_source(mechanism, snapshot)
            mechanisms[mechanism] = source
            rows.append(_candidate(
                "installed_route", "INSTALLED_ROUTE_MEMBERSHIP",
                f"installed-route:{kind}:{member['coordinate']}",
                source_refs=_source_refs(
                    snapshot, "src/verifier/domains/inventory.py",
                    *(tuple() if source is None else (source,)),
                ),
                metadata={"object_kind": kind, "tier": tier, **member,
                          "mechanism_source_status":
                              "MAPPED" if source is not None else "UNKNOWN"},
            ))
    for mechanism, source in sorted(mechanisms.items()):
        rows.append(_candidate(
            "installed_mechanism", "INSTALLED_CHECKING_MECHANISM",
            "installed-mechanism:" + mechanism,
            source_refs=_source_refs(
                snapshot, *(tuple() if source is None else (source,))
            ),
            metadata={"checking_mechanism": mechanism,
                      "source_path": source,
                      "mapping_status": "MAPPED" if source else "UNKNOWN"},
        ))
    return rows, inventory


def _structural_rows(snapshot: dict[str, Any], inventory: dict[str, Any],
                     ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    families = application_requirements.installed_families(
        [kind.value for kind in ObjectKind]
    )
    route_rows = [
        {"object_kind": cell["object_kind"], **member}
        for cell in inventory["family_cells"] if cell["tier"] == 1
        for member in cell["registered_route_memberships"]
    ]
    structural = [
        {"object_kind": family["represented_kind"], **member}
        for family in families for member in family["members"]
    ]
    structural.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    route_rows.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    _require(len(families) == 26 and len(structural) == 52 and len(route_rows) == 45,
             "STRUCTURAL_ROUTE_DENOMINATOR_DIFFERS")
    structural_by_id = {(row["object_kind"], row["coordinate"]): row
                        for row in structural}
    routes_by_id = {(row["object_kind"], row["coordinate"]): row
                    for row in route_rows}
    _require(len(structural_by_id) == 52 and len(routes_by_id) == 45,
             "STRUCTURAL_ROUTE_ID_DUPLICATED")
    shared = sorted(set(structural_by_id) & set(routes_by_id))
    structural_only = sorted(set(structural_by_id) - set(routes_by_id))
    route_only = sorted(set(routes_by_id) - set(structural_by_id))
    _require((len(shared), len(structural_only), len(route_only)) == (27, 25, 18),
             "STRUCTURAL_ROUTE_CROSSWALK_DIFFERS")
    _require(all(structural_by_id[key]["proposition_digest"]
                 == routes_by_id[key]["proposition_digest"] for key in shared),
             "STRUCTURAL_ROUTE_PROPOSITION_DIFFERS")
    refs = _source_refs(
        snapshot,
        "src/verifier/domains/contracts/application_requirements.py",
        "src/verifier/runtime/core_tier_progression.py",
        "src/verifier/domains/inventory.py",
    )
    rows = []
    for family in families:
        rows.append(_candidate(
            "structural_family", "INSTALLED_STRUCTURAL_FAMILY",
            "structural-family:" + family["represented_kind"], source_refs=refs,
            metadata={key: value for key, value in family.items() if key != "members"}
                     | {"membership_count": len(family["members"])},
        ))
    for row in structural:
        key = (row["object_kind"], row["coordinate"])
        rows.append(_candidate(
            "structural_membership", "INSTALLED_STRUCTURAL_MEMBERSHIP",
            f"structural-membership:{key[0]}:{key[1]}", source_refs=refs,
            metadata=row,
        ))
        route = routes_by_id.get(key)
        rows.append(_candidate(
            "structural_route_crosswalk", "STRUCTURAL_TO_ROUTE_CROSSWALK",
            f"structural-route-crosswalk:structural:{key[0]}:{key[1]}",
            source_refs=refs,
            metadata={"object_kind": key[0], "coordinate": key[1],
                      "crosswalk_status": "MATCHED" if route else "STRUCTURAL_ONLY",
                      "route_obligation_id":
                          f"{key[0]}:{key[1]}" if route else None},
        ))
    for key in route_only:
        rows.append(_candidate(
            "structural_route_crosswalk", "STRUCTURAL_TO_ROUTE_CROSSWALK",
            f"structural-route-crosswalk:route:{key[0]}:{key[1]}",
            source_refs=refs,
            metadata={"object_kind": key[0], "coordinate": key[1],
                      "crosswalk_status": "ROUTE_ONLY",
                      "route_obligation_id": f"{key[0]}:{key[1]}"},
        ))
    crosswalk = {
        "status": "NOT_ESTABLISHED",
        "structural_membership_count": 52,
        "route_tier1_membership_count": 45,
        "shared_identity_count": 27,
        "structural_only_identity_count": 25,
        "route_only_identity_count": 18,
        "structural_identity_digest": value_digest(structural),
        "route_identity_digest": value_digest(route_rows),
        "shared_identity_digest": value_digest([
            {"object_kind": kind, "coordinate": coordinate}
            for kind, coordinate in shared
        ]),
        "claim_boundary": (
            "The exact 52-to-45 crosswalk has a 27-identity intersection. "
            "Denominator non-equality remains explicit and is not semantic closure."
        ),
    }
    return rows, crosswalk


def _non_route_gate_rows(root: Path, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in snapshot["files"]:
        relative = item["path"]
        if not relative.startswith("src/verifier/") or not relative.endswith(".py"):
            continue
        tree = _parse_python(root, relative)
        assignments: dict[str, ast.AST] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value
        for name in sorted(set(assignments) & {"FULL_GATES", "_FULL_GATE_OBJECTIVES"}):
            try:
                value = ast.literal_eval(assignments[name])
            except (ValueError, TypeError) as exc:
                raise EstateError("NON_ROUTE_GATE_REGISTRY_NOT_LITERAL") from exc
            members = list(value) if isinstance(value, (tuple, list, dict)) else []
            _require(bool(members), "NON_ROUTE_GATE_REGISTRY_INVALID")
            for member in sorted(members):
                rows.append(_candidate(
                    "non_route_gate", "NON_ROUTE_GATE_REGISTRY_MEMBER",
                    f"non-route-gate:{relative}:{name}:{member}",
                    source_refs=_source_refs(snapshot, relative),
                    metadata={"registry_path": relative, "registry_symbol": name,
                              "gate_id": member},
                ))
    _require(bool(rows), "NON_ROUTE_GATE_REGISTRY_MISSING")
    return rows


def _parser_routes(parser: argparse.ArgumentParser) -> list[tuple[str, bool]]:
    routes: dict[str, bool] = {}

    def visit(selected: argparse.ArgumentParser, prefix: tuple[str, ...], depth: int) -> None:
        _require(depth <= MAX_CLI_DEPTH, "CLI_ROUTE_DEPTH_EXHAUSTED")
        actions = [action for action in selected._actions
                   if isinstance(action, argparse._SubParsersAction)]
        _require(len(actions) <= 1, "CLI_MULTIPLE_SUBPARSER_REGISTRIES")
        if not actions:
            if prefix:
                routes["/".join(prefix)] = True
            return
        choices = actions[0].choices
        for name in sorted(choices):
            path = prefix + (name,)
            route = "/".join(path)
            routes[route] = False
            visit(choices[name], path, depth + 1)
            _require(len(routes) <= MAX_CLI_ROUTES, "CLI_ROUTE_CAPACITY_EXHAUSTED")

    visit(parser, (), 0)
    return sorted(routes.items())


def _numeric_preparser_values(tree: ast.Module) -> tuple[str, ...]:
    main = next((node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == "main"), None)
    _require(main is not None, "CLI_MAIN_MISSING")
    values: set[str] = set()
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        constants = {item.value for item in ast.walk(node.test)
                     if isinstance(item, ast.Constant) and isinstance(item.value, str)}
        if "polish" not in constants:
            continue
        for item in ast.walk(node.test):
            if isinstance(item, (ast.Tuple, ast.List)):
                literal = [element.value for element in item.elts
                           if isinstance(element, ast.Constant)
                           and isinstance(element.value, str)]
                if len(literal) == len(item.elts) and literal \
                        and all(value.isdigit() for value in literal):
                    values.update(literal)
    _require(bool(values), "CLI_NUMERIC_PREPARSER_ROUTE_MISSING")
    return tuple(sorted(values, key=int))


def _cli_rows(root: Path, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    relative = "src/verifier/runtime/public_cli.py"
    refs = _source_refs(snapshot, relative)
    _require(bool(refs), "PUBLIC_CLI_SOURCE_UNTRACKED")
    rows = [
        _candidate(
            "public_cli_route", "PUBLIC_CLI_PARSER_ROUTE", "public-cli-route:" + route,
            source_refs=refs, metadata={"route": route, "leaf": leaf},
        )
        for route, leaf in _parser_routes(public_cli.build_parser())
    ]
    tree = _parse_python(root, relative)
    for value in _numeric_preparser_values(tree):
        rows.append(_candidate(
            "public_cli_preparser_route", "NUMERIC_PREPARSER_ROUTE",
            f"public-cli-preparser-route:polish/{value}", source_refs=refs,
            metadata={"route": f"polish/{value}", "parser_registered": False},
        ))
    return rows


def _pyproject_rows(root: Path, snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    relative = "pyproject.toml"
    refs = _source_refs(snapshot, relative)
    _require(bool(refs), "PYPROJECT_UNTRACKED")
    raw = (root / relative).read_bytes()
    _require(len(raw) <= MAX_AST_BYTES, "PYPROJECT_CAPACITY_EXHAUSTED")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise EstateError("PYPROJECT_INVALID") from exc
    scripts = value.get("project", {}).get("scripts")
    _require(type(scripts) is dict and bool(scripts), "CONSOLE_ALIAS_REGISTRY_INVALID")
    rows = [_candidate(
        "console_alias", "CONSOLE_SCRIPT_ALIAS", "console-alias:" + name,
        source_refs=refs, metadata={"name": name, "target": target},
    ) for name, target in sorted(scripts.items())]
    patterns = value.get("tool", {}).get("setuptools", {}).get(
        "package-data", {}
    ).get("verifier")
    _require(type(patterns) is list and all(type(item) is str for item in patterns),
             "PACKAGE_DATA_REGISTRY_INVALID")
    return rows, sorted(patterns)


def _lazy_export_rows(root: Path, snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    relative = "src/verifier/__init__.py"
    tree = _parse_python(root, relative)
    exports = _literal_assignment(tree, "_LAZY_EXPORTS")
    _require(type(exports) is dict and bool(exports), "PUBLIC_LAZY_EXPORTS_INVALID")
    refs = _source_refs(snapshot, relative)
    rows = []
    for name, target in sorted(exports.items()):
        _require(type(name) is str and isinstance(target, tuple) and len(target) == 2
                 and all(type(item) is str for item in target),
                 "PUBLIC_LAZY_EXPORTS_INVALID")
        rows.append(_candidate(
            "public_lazy_export", "PUBLIC_API_LAZY_EXPORT", "public-lazy-export:" + name,
            source_refs=refs, metadata={"name": name, "module": target[0],
                                       "symbol": target[1]},
        ))
    return rows, exports


def _domain_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    value = domain_catalog_module.domain_catalog(include_accountable=True)
    domains = value.get("domains")
    _require(type(domains) is dict and bool(domains), "DOMAIN_CATALOG_INVALID")
    refs = _source_refs(snapshot, "src/verifier/domains/catalog.py")
    rows = []
    for name, domain in sorted(domains.items()):
        rows.append(_candidate(
            "domain", "DOMAIN_CATALOG_ENTRY", "domain:" + name,
            source_refs=refs,
            metadata={"domain": name, "scope": domain["scope"],
                      "check_count": len(domain["checks"])},
        ))
        for check in domain["checks"]:
            rows.append(_candidate(
                "domain_check", "DOMAIN_CATALOG_CHECK",
                f"domain-check:{name}:{check['id']}", source_refs=refs,
                metadata={"domain": name, **check},
            ))
    return rows


def _interoperability_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    registry = reference_component_registry()
    refs = _source_refs(
        snapshot, "src/verifier/interoperability/reference_catalog.py",
        "src/verifier/interoperability/catalog.py",
    )
    return [_candidate(
        "interoperability_component", "INTEROPERABILITY_COMPONENT",
        "interoperability-component:" + component.component_id,
        source_refs=refs, metadata=component.to_dict(),
    ) for component in registry.components]


def _schema_rows(root: Path, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    canonical_ids: list[str] = []
    for item in snapshot["files"]:
        relative = item["path"]
        if not (relative.startswith("receipts/schema/")
                or relative.startswith("src/verifier/schemas/")) \
                or not relative.endswith(".json"):
            continue
        try:
            value = json.loads((root / relative).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise EstateError("SCHEMA_JSON_INVALID") from exc
        expected = "https://timelordraps.github.io/verifier/schemas/" + Path(relative).name
        _require(type(value) is dict and value.get("$id") == expected,
                 "SCHEMA_CANONICAL_ID_DIFFERS")
        canonical_ids.append(expected)
        rows.append(_candidate(
            "schema", "CANONICAL_JSON_SCHEMA", "schema:" + relative,
            source_refs=_source_refs(snapshot, relative),
            metadata={"path": relative, "canonical_id": expected},
        ))
    _require(bool(rows), "SCHEMA_CENSUS_EMPTY")
    _require(len(canonical_ids) == len(set(canonical_ids)),
             "SCHEMA_CANONICAL_ID_DUPLICATED")
    return rows


def _native_compatibility_rows(root: Path, snapshot: dict[str, Any],
                               inventory: dict[str, Any], exports: dict[str, Any],
                               ) -> list[dict[str, Any]]:
    rows = []
    for cell in inventory["family_cells"]:
        for member in cell["registered_route_memberships"]:
            source = _mechanism_source(member["checking_mechanism"], snapshot)
            rows.append(_candidate(
                "native_route", "NATIVE_INSTALLED_ROUTE",
                f"native-route:{cell['object_kind']}:{member['coordinate']}",
                source_refs=_source_refs(
                    snapshot, *(tuple() if source is None else (source,))
                ),
                metadata={"object_kind": cell["object_kind"], "tier": cell["tier"],
                          "coordinate": member["coordinate"],
                          "checking_mechanism": member["checking_mechanism"]},
            ))
    compatibility_modules = {
        "verifier.core.depth", "verifier.core.reproducibility",
        "verifier.data.graph_level",
    }
    for name, target in sorted(exports.items()):
        if target[0] in compatibility_modules or target[0].startswith("verifier.layer4"):
            relative = "src/" + target[0].replace(".", "/") + ".py"
            rows.append(_candidate(
                "compatibility_route", "PUBLIC_COMPATIBILITY_ROUTE",
                "compatibility-route:public:" + name,
                source_refs=_source_refs(snapshot, "src/verifier/__init__.py", relative),
                metadata={"public_name": name, "module": target[0],
                          "symbol": target[1]},
            ))
    for item in snapshot["files"]:
        relative = item["path"]
        if not relative.startswith("src/verifier/layer4/") or not relative.endswith(".py"):
            continue
        tree = _parse_python(root, relative)
        module = relative[len("src/"):-3].replace("/", ".")
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rows.append(_candidate(
                    "compatibility_route", "RETAINED_MODULE_COMPATIBILITY_ROUTE",
                    f"compatibility-route:{module}:{node.name}",
                    source_refs=_source_refs(snapshot, relative),
                    metadata={"module": module, "symbol": node.name},
                ))
    _require(any(row["category"] == "compatibility_route" for row in rows),
             "COMPATIBILITY_ROUTE_CENSUS_EMPTY")
    return rows


def _package_data_rows(snapshot: dict[str, Any], patterns: list[str]) -> list[dict[str, Any]]:
    rows = []
    for item in snapshot["files"]:
        relative = item["path"]
        if not relative.startswith("src/verifier/"):
            continue
        package_relative = relative[len("src/verifier/"):]
        for pattern in patterns:
            if fnmatch(package_relative, pattern):
                rows.append(_candidate(
                    "package_data_candidate", "SETUPTOOLS_PACKAGE_DATA_CANDIDATE",
                    f"package-data-candidate:{pattern}:{package_relative}",
                    source_refs=[{"path": relative, "sha256": item["sha256"]}],
                    metadata={"pattern": pattern, "package_relative_path": package_relative},
                ))
    _require(bool(rows), "PACKAGE_DATA_CENSUS_EMPTY")
    return rows


def _unresolved_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    refs = _source_refs(snapshot, "pyproject.toml", "src/verifier/runtime/public_cli.py")
    unresolved = {
        "external-plugin-estate": "External plugin entry points are not imported or executed.",
        "generated-build-backend-estate": (
            "Bytes under the explicit ignored cache/build exclusion taxonomy "
            "are not verified by the candidate-source census."
        ),
        "runtime-environment-estate": "Installed distributions, operating-system state, and external commands are not inferred from source.",
    }
    return [_candidate(
        "unresolved_surface", "EXPLICIT_UNKNOWN_SURFACE",
        "unresolved-surface:" + identifier, source_refs=refs,
        metadata={"surface_id": identifier, "enumeration_status": "UNKNOWN",
                  "reason": reason},
    ) for identifier, reason in sorted(unresolved.items())]


def _enumerate(root: Path, snapshot: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_source_file_rows(root, snapshot))
    rows.extend(_python_rows(root, snapshot))
    installed, inventory = _installed_route_rows(snapshot)
    rows.extend(installed)
    structural, crosswalk = _structural_rows(snapshot, inventory)
    rows.extend(structural)
    rows.extend(_non_route_gate_rows(root, snapshot))
    rows.extend(_cli_rows(root, snapshot))
    pyproject_rows, package_patterns = _pyproject_rows(root, snapshot)
    rows.extend(pyproject_rows)
    lazy_rows, exports = _lazy_export_rows(root, snapshot)
    rows.extend(lazy_rows)
    rows.extend(_domain_rows(snapshot))
    rows.extend(_interoperability_rows(snapshot))
    rows.extend(_schema_rows(root, snapshot))
    rows.extend(_native_compatibility_rows(root, snapshot, inventory, exports))
    rows.extend(_package_data_rows(snapshot, package_patterns))
    rows.extend(_unresolved_rows(snapshot))
    _require(0 < len(rows) <= MAX_CANDIDATES, "CANDIDATE_CAPACITY_EXHAUSTED")
    rows.sort(key=lambda row: row["candidate_id"])
    _require(len({row["candidate_id"] for row in rows}) == len(rows),
             "CANDIDATE_ID_DUPLICATED")
    observed_categories = {row["category"] for row in rows}
    _require(observed_categories == set(REQUIRED_CATEGORIES),
             "ESTATE_CATEGORY_SET_DIFFERS")
    return rows, crosswalk


def build_candidate_estate(root: str | Path, *, expected_repository: str,
                           expected_revision: str) -> dict[str, Any]:
    """Build one pre/post byte-bound candidate census or fail closed."""

    selected = Path(root).resolve(strict=True)
    _require(selected.is_dir(), "REPOSITORY_ROOT_INVALID")
    coordinate_before = _git_coordinate(selected)
    _require(coordinate_before == {
        "repository": expected_repository, "revision": expected_revision,
    }, "SOURCE_COORDINATE_DIFFERS")
    before = capture_candidate_source_census(selected)
    _runtime_source_binding(selected, before)
    candidates, crosswalk = _enumerate(selected, before)
    _runtime_source_binding(selected, before)
    coordinate_after = _git_coordinate(selected)
    after = capture_candidate_source_census(selected)
    _require(coordinate_after == coordinate_before, "SOURCE_COORDINATE_MUTATED")
    _require(
        after == before,
        "CANDIDATE_SOURCE_MUTATED",
    )
    category_summaries = []
    for category in REQUIRED_CATEGORIES:
        selected_rows = [row for row in candidates if row["category"] == category]
        _require(bool(selected_rows), "ESTATE_CATEGORY_EMPTY")
        category_summaries.append({
            "category": category,
            "mechanical_status": "PASS",
            "candidate_count": len(selected_rows),
            "candidate_digest": value_digest(selected_rows),
            "semantic_status": "NOT_ESTABLISHED",
        })
    source_coordinate = {
        **coordinate_before,
        "candidate_source_file_count": before["file_count"],
        "candidate_source_byte_count": before["total_bytes"],
        "candidate_source_census_digest": before["census_digest"],
        "tracked_file_count": before["provenance_counts"]["GIT_TRACKED"],
        "untracked_nonignored_file_count": before["provenance_counts"][
            "WORKTREE_UNTRACKED_NONIGNORED"
        ],
    }
    body = {
        "schema_version": ESTATE_SCHEMA,
        "mechanical_census_status": "PASS",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "source_coordinate": source_coordinate,
        "pre_source_census": before,
        "post_source_census": after,
        "required_categories": list(REQUIRED_CATEGORIES),
        "category_summaries": category_summaries,
        "structural_route_crosswalk": crosswalk,
        "candidate_count": len(candidates),
        "candidate_universe_digest": value_digest(candidates),
        "candidates": candidates,
        "applicability_ledger": None,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return {**body, "estate_digest": value_digest(body)}


def applicability_ledger_template(estate: dict[str, Any]) -> dict[str, Any]:
    """Return an all-UNKNOWN exact-ID ledger template for independent selection."""

    rows = [{
        "candidate_id": row["candidate_id"],
        "candidate_digest": row["candidate_digest"],
        "applicability_status": "UNKNOWN",
        "authority_status": "NOT_ESTABLISHED",
        "evidence_status": "NOT_ESTABLISHED",
        "authority_digest": None,
        "evidence_digest": None,
        "justification": "Independent applicability, authority, and evidence are not supplied.",
    } for row in estate["candidates"]]
    body = {
        "schema_version": APPLICABILITY_LEDGER_SCHEMA,
        "source_coordinate": estate["source_coordinate"],
        "candidate_universe_digest": estate["candidate_universe_digest"],
        "rows": rows,
    }
    return {**body, "ledger_digest": value_digest(body)}


def _strict_json(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= MAX_LEDGER_BYTES,
             "APPLICABILITY_LEDGER_CAPACITY_EXHAUSTED")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            _require(key not in result, "APPLICABILITY_LEDGER_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise EstateError("APPLICABILITY_LEDGER_INVALID") from exc
    _require(type(value) is dict and raw == canonical_bytes(value),
             "APPLICABILITY_LEDGER_NOT_CANONICAL")
    return value


def validate_applicability_ledger(estate: dict[str, Any], ledger_bytes: bytes, *,
                                  expected_ledger_digest: str) -> dict[str, Any]:
    """Validate exact candidate coverage without trusting submitted PASS labels."""

    value = _strict_json(ledger_bytes)
    _require(set(value) == {
        "schema_version", "source_coordinate", "candidate_universe_digest",
        "rows", "ledger_digest",
    }, "APPLICABILITY_LEDGER_FIELDS_DIFFER")
    body = {key: item for key, item in value.items() if key != "ledger_digest"}
    _require(type(expected_ledger_digest) is str
             and _SHA256.fullmatch(expected_ledger_digest) is not None
             and value["ledger_digest"] == expected_ledger_digest
             and value["ledger_digest"] == value_digest(body),
             "APPLICABILITY_LEDGER_DIGEST_DIFFERS")
    _require(value["schema_version"] == APPLICABILITY_LEDGER_SCHEMA
             and value["source_coordinate"] == estate["source_coordinate"]
             and value["candidate_universe_digest"]
                 == estate["candidate_universe_digest"],
             "APPLICABILITY_LEDGER_SOURCE_OR_UNIVERSE_DIFFERS")
    candidates = {row["candidate_id"]: row for row in estate["candidates"]}
    rows = value["rows"]
    _require(type(rows) is list and len(rows) == len(candidates),
             "APPLICABILITY_LEDGER_DENOMINATOR_DIFFERS")
    observed: set[str] = set()
    caller_pass_count = 0
    for row in rows:
        _require(type(row) is dict and set(row) == {
            "candidate_id", "candidate_digest", "applicability_status",
            "authority_status", "evidence_status", "authority_digest",
            "evidence_digest", "justification",
        }, "APPLICABILITY_LEDGER_ROW_FIELDS_DIFFER")
        identifier = row["candidate_id"]
        _require(identifier in candidates and identifier not in observed,
                 "APPLICABILITY_LEDGER_ID_SET_DIFFERS")
        observed.add(identifier)
        _require(row["candidate_digest"] == candidates[identifier]["candidate_digest"],
                 "APPLICABILITY_LEDGER_CANDIDATE_SUBSTITUTED")
        _require(row["applicability_status"] in {
            "APPLICABLE", "NOT_APPLICABLE", "UNKNOWN",
        } and row["authority_status"] in {
            "PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED",
        } and row["evidence_status"] in {
            "PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED",
        } and type(row["justification"]) is str
          and 0 < len(row["justification"]) <= 4096,
          "APPLICABILITY_LEDGER_STATE_INVALID")
        for status_name, digest_name in (
            ("authority_status", "authority_digest"),
            ("evidence_status", "evidence_digest"),
        ):
            digest = row[digest_name]
            _require((row[status_name] == "PASS"
                      and type(digest) is str and _SHA256.fullmatch(digest) is not None)
                     or (row[status_name] != "PASS" and digest is None),
                     "APPLICABILITY_LEDGER_EVIDENCE_INVALID")
        caller_pass_count += (
            row["applicability_status"] == "APPLICABLE"
            and row["authority_status"] == "PASS"
            and row["evidence_status"] == "PASS"
        )
    _require(observed == set(candidates), "APPLICABILITY_LEDGER_ID_SET_DIFFERS")
    result = {
        "schema_version": APPLICABILITY_RESULT_SCHEMA,
        "mechanical_validation_status": "PASS",
        "candidate_count": len(candidates),
        "candidate_universe_digest": estate["candidate_universe_digest"],
        "ledger_digest": value["ledger_digest"],
        "caller_declared_pass_count": caller_pass_count,
        "caller_pass_authentication": "NOT_ESTABLISHED",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return {**result, "result_digest": value_digest(result)}


__all__ = [
    "APPLICABILITY_LEDGER_SCHEMA", "APPLICABILITY_RESULT_SCHEMA",
    "CANDIDATE_SOURCE_CENSUS_SCHEMA", "CLAIM_BOUNDARY", "ESTATE_SCHEMA",
    "IGNORED_EXCLUSION_TAXONOMY", "IGNORED_EXCLUSION_TAXONOMY_DIGEST",
    "EstateError", "REQUIRED_CATEGORIES",
    "applicability_ledger_template", "build_candidate_estate", "bytes_digest",
    "canonical_bytes", "capture_candidate_source_census",
    "validate_applicability_ledger", "value_digest",
]
