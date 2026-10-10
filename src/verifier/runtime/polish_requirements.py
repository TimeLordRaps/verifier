"""Pinned requirement coverage for Verifier Standard (VSTD) polish assessment.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Counts are dimensionless; encoded input limits use bytes. The inventory gate
compares an externally selected numbered inventory, then invokes the existing
native polish assessment. The separate core-self-polish path binds an exact Git
source state and replays the installed structural compiler and selected native
VERIFIER certificates. Neither path issues polished status or supplies authority.
"""
from __future__ import annotations

import base64
import inspect
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import (
    NamespaceObject, ObjectCoordinate, ObjectKind, composition_digest,
)
from verifier.domains.contracts import application_requirements as application_compiler
from verifier.domains.contracts import object_facets, typed_facets
from verifier.domains.contracts.current_object_routes import (
    CurrentObjectRouteRefusal, current_object_route_catalog, select_current_object_route,
)
from verifier.runtime import core_application_release, polish
from verifier.runtime.polish_capacity import Budget, CapacityExceeded, CEILINGS

INVENTORY_VERSION = "verifier-polish-requirements-inventory-1"
ASSESSMENT_VERSION = "verifier-polish-requirements-assessment-1"
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
BOUNDARY = (
    "Coverage of a separately pinned finite declared numbered inventory only. "
    "Digest selection is not inventory authentication or exhaustive applicability. "
    "Native replay, authority, public checkability and polished issuance remain distinct."
)
CORE_SELF_POLISH_SELECTION = "verifier-core-self-polish-selection-1"
CORE_SELF_POLISH_SOURCE = "verifier-core-self-polish-source-manifest-2"
CORE_SELF_POLISH_RECEIPT = "verifier-core-self-polish-receipt-1"
CORE_SELF_POLISH_REPLAY = "verifier-core-self-polish-replay-1"
CORE_SELF_POLISH_MECHANISM_ID = "verifier.core-self-polish.exact-selected-structural-replay.1"
MAX_SOURCE_FILES = 8192
MAX_SOURCE_BYTES = 128 * 1024 * 1024
CORE_SELF_POLISH_BOUNDARY = (
    "PASS establishes the exact externally digest-pinned CORE-SELF-POLISH-1 "
    "selection for one source-bound VERIFIER object under the installed "
    "retained-namespace-structure-1 profile: exact source state, instructions, "
    "compiler inputs, contexts, native mechanisms and two selected tier-1 "
    "certificates replay. It does not establish full-application completeness, "
    "selection authority, public availability, human acceptance, release "
    "authorization or polished status."
)


class RequirementRefusal(ValueError):
    """Fixed diagnostic; never carry input witnesses or exception text."""


class MechanismBindingUnavailable(ValueError):
    """Installed metadata cannot bind the mechanism; coverage remains UNKNOWN."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RequirementRefusal(reason)


def requirements_catalog_digest() -> str:
    """Pin the installed registered propositions, not an exhaustive requirement set."""
    rows = sorted(current_object_route_catalog(), key=lambda row: (row["semantic_version"], row["objective"]))
    return polish._digest(canonical_bytes(rows))


def registered_objective_binding(semantic_version: str, coordinate: str, represented_kind: str) -> dict[str, str]:
    """Read installed native metadata for an admitted objective and kind.

    No submitted import path, function, module or callback is executed. The native
    checker still validates its policy and evidence during replay. The fixed
    CORE-SELF-POLISH-1 branch is admitted only for VERIFIER and binds this exact
    source-state/compiler/native orchestration mechanism.
    """
    core_coordinate = core_application_release.full_gate_coordinate("CORE_SELF_POLISH")
    if semantic_version == core_coordinate["semantic_version"]:
        _require(coordinate == core_coordinate["objective"]
                 and represented_kind == "VERIFIER", "REGISTERED_OBJECTIVE_KIND_DIFFERS")
        return {"mechanism_id": CORE_SELF_POLISH_MECHANISM_ID,
                "mechanism_digest": core_self_polish_mechanism_digest(),
                "proposition_digest": core_coordinate["proposition_digest"]}
    _require(type(semantic_version) is str and semantic_version ==
             "verifier-current-object-obligations-1", "SEMANTIC_VERSION_UNSUPPORTED")
    route = select_current_object_route(semantic_version=semantic_version,
        objective=coordinate, represented_kind=represented_kind)
    module = inspect.getmodule(route.replay)
    if module is None or not callable(getattr(module, "mechanism_digest", None)):
        raise MechanismBindingUnavailable("installed mechanism binding unavailable")
    # This is a registered source module, never a submitted dispatcher. Security
    # binds each selected kind in its mechanism; legacy native mechanisms do not.
    args = (represented_kind,) if module.__name__ == "verifier.domains.contracts.subject_security" else ()
    try:
        inspect.signature(module.mechanism_digest).bind(*args)
    except (TypeError, ValueError) as exc:
        raise MechanismBindingUnavailable("installed mechanism signature unsupported") from exc
    return {"mechanism_id": polish._text(module.MECHANISM_ID),
            "mechanism_digest": polish._hash(module.mechanism_digest(*args)),
            "proposition_digest": polish._hash(route.module.PROPOSITION_DIGEST)}


def mechanism_digest() -> str:
    """Bind this gate, its packaged specification and the delegated polish checker."""
    spec = Path(__file__).parents[1] / "standard" / "POLISH_REQUIREMENTS.md"
    return polish._digest(canonical_bytes({
        "gate": polish._digest(Path(__file__).read_bytes()),
        "specification": polish._digest(spec.read_bytes()),
        "native_polish": polish.mechanism_digest(),
    }))


def core_self_polish_mechanism_digest() -> str:
    """Bind the narrow self-replay orchestrator to every delegated mechanism."""
    return polish._digest(canonical_bytes({
        "schema_version": "verifier-core-self-polish-mechanism-1",
        "mechanism_id": CORE_SELF_POLISH_MECHANISM_ID,
        "requirements_gate": mechanism_digest(),
        "application_compiler": application_compiler.mechanism_digest(),
        "native_polish": polish.mechanism_digest(),
        "core_coordinate": core_application_release.full_gate_coordinate("CORE_SELF_POLISH"),
        "selected_source_bindings": core_self_polish_source_bindings(),
    }))


def core_self_polish_source_bindings() -> dict[str, str]:
    """Return the minimum executed source set the selected source must contain."""
    bindings = {"src/verifier/" + name: pin for name, pin
                in application_compiler.source_bindings().items()}
    direct = {
        "src/verifier/runtime/polish_requirements.py": Path(__file__),
        "src/verifier/standard/POLISH_REQUIREMENTS.md": (
            Path(__file__).parents[1] / "standard" / "POLISH_REQUIREMENTS.md"),
        "src/verifier/runtime/polish.py": Path(polish.__file__),
        "src/verifier/runtime/polish_capacity.py": Path(__file__).with_name("polish_capacity.py"),
        "src/verifier/runtime/self_polish_estate.py": Path(__file__).with_name(
            "self_polish_estate.py"
        ),
        "src/verifier/runtime/core_application_release.py": Path(core_application_release.__file__),
        "src/verifier/domains/contracts/current_object_routes.py": (
            Path(__file__).parents[1] / "domains" / "contracts" / "current_object_routes.py"),
    }
    try:
        for name, path in direct.items():
            observed = polish._digest(path.resolve().read_bytes())
            _require(name not in bindings or bindings[name] == observed,
                     "INSTALLED_MECHANISM_SOURCE_DISAGREES")
            bindings[name] = observed
    except OSError as exc:
        raise MechanismBindingUnavailable("installed mechanism source unavailable") from exc
    return dict(sorted(bindings.items()))


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MechanismBindingUnavailable("git source binding unavailable") from exc
    if completed.returncode != 0:
        raise MechanismBindingUnavailable("git source binding unavailable")
    return completed.stdout


def _source_path(value: bytes) -> str:
    try:
        name = value.decode("utf-8")
    except UnicodeError as exc:
        raise RequirementRefusal("SOURCE_PATH_INVALID") from exc
    _require(type(name) is str and bool(name) and len(name) <= 4096
             and "\\" not in name and not name.startswith("/")
             and all(part not in ("", ".", "..") for part in name.split("/")),
             "SOURCE_PATH_INVALID")
    return name


def capture_core_self_polish_source(root: str | Path) -> dict[str, Any]:
    """Capture the exact candidate-source census plus repository state.

    The shared estate selector binds every Git-tracked working byte and every
    bounded nonignored untracked ordinary file. It also binds index modes, exact
    porcelain status, and the ignored-path exclusion boundary. Candidate bytes
    therefore do not need to be staged to become visible, and no untracked source
    is silently admitted outside the census.
    """
    selected = Path(root).resolve()
    _require(selected.is_dir(), "SOURCE_ROOT_INVALID")
    top_raw = _git(selected, "rev-parse", "--show-toplevel").rstrip(b"\r\n")
    try:
        top = Path(top_raw.decode("utf-8")).resolve()
    except UnicodeError as exc:
        raise MechanismBindingUnavailable("git source binding unavailable") from exc
    _require(os.path.normcase(str(top)) == os.path.normcase(str(selected)),
             "SOURCE_ROOT_DIFFERS")
    head = _git(selected, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _git(selected, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    _require(len(head) == 40 and len(tree) == 40
             and all(char in "0123456789abcdef" for char in head + tree),
             "SOURCE_GIT_COORDINATE_INVALID")
    try:
        from verifier.runtime import self_polish_estate
    except ImportError as exc:
        raise MechanismBindingUnavailable(
            "candidate source census unavailable"
        ) from exc
    try:
        census = self_polish_estate.capture_candidate_source_census(selected)
    except self_polish_estate.EstateError as exc:
        raise RequirementRefusal(str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise MechanismBindingUnavailable(
            "candidate source census unavailable"
        ) from exc
    _require(
        type(census) is dict
        and census.get("schema_version")
            == "verifier-self-polish-candidate-source-census-1",
        "CANDIDATE_SOURCE_CENSUS_INVALID",
    )
    status = _git(selected, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    _require(
        census.get("git_status_digest") == polish._digest(status),
        "CANDIDATE_SOURCE_STATUS_DIFFERS",
    )
    counts = census["provenance_counts"]
    return {"schema_version": CORE_SELF_POLISH_SOURCE,
            "git_head": head, "git_tree": tree,
            "worktree_clean": status == b"",
            "worktree_status_digest": polish._digest(status),
            "candidate_source_census_digest": census["census_digest"],
            "candidate_source_file_count": census["file_count"],
            "candidate_source_bytes": census["total_bytes"],
            "tracked_file_count": counts["GIT_TRACKED"],
            "untracked_nonignored_file_count":
                counts["WORKTREE_UNTRACKED_NONIGNORED"],
            "candidate_source_census": census}


def _source_manifest(value: Any) -> dict[str, Any]:
    polish._keys(value, "schema_version git_head git_tree worktree_clean "
                 "worktree_status_digest candidate_source_census_digest "
                 "candidate_source_file_count candidate_source_bytes "
                 "tracked_file_count untracked_nonignored_file_count "
                 "candidate_source_census")
    _require(value["schema_version"] == CORE_SELF_POLISH_SOURCE,
             "SOURCE_MANIFEST_VERSION_UNSUPPORTED")
    for field in ("git_head", "git_tree"):
        _require(type(value[field]) is str and len(value[field]) == 40
                 and all(char in "0123456789abcdef" for char in value[field]),
                 "SOURCE_GIT_COORDINATE_INVALID")
    _require(type(value["worktree_clean"]) is bool,
             "SOURCE_WORKTREE_STATE_INVALID")
    polish._hash(value["worktree_status_digest"])
    polish._hash(value["candidate_source_census_digest"])
    _require(type(value["candidate_source_file_count"]) is int
             and 1 <= value["candidate_source_file_count"] <= 20_000
             and type(value["candidate_source_bytes"]) is int
             and 0 <= value["candidate_source_bytes"] <= 1024 * 1024 * 1024
             and type(value["tracked_file_count"]) is int
             and value["tracked_file_count"] >= 1
             and type(value["untracked_nonignored_file_count"]) is int
             and value["untracked_nonignored_file_count"] >= 0,
             "SOURCE_CAPACITY_DECLARATION_INVALID")
    census = value["candidate_source_census"]
    polish._keys(census, "schema_version file_count total_bytes "
                 "provenance_counts git_index_digest git_status_digest "
                 "files ignored_scan census_digest")
    _require(census["schema_version"]
                 == "verifier-self-polish-candidate-source-census-1",
             "CANDIDATE_SOURCE_CENSUS_VERSION_UNSUPPORTED")
    polish._hash(census["git_index_digest"])
    polish._hash(census["git_status_digest"])
    polish._hash(census["census_digest"])
    _require(census["census_digest"] == polish._digest(canonical_bytes({
                 key: item for key, item in census.items()
                 if key != "census_digest"
             })), "CANDIDATE_SOURCE_CENSUS_DIGEST_DIFFERS")
    counts = census["provenance_counts"]
    _require(type(counts) is dict
             and set(counts) == {
                 "GIT_TRACKED", "WORKTREE_UNTRACKED_NONIGNORED"
             }
             and counts["GIT_TRACKED"] == value["tracked_file_count"]
             and counts["WORKTREE_UNTRACKED_NONIGNORED"]
                 == value["untracked_nonignored_file_count"]
             and sum(counts.values()) == value["candidate_source_file_count"],
             "CANDIDATE_SOURCE_PROVENANCE_COUNT_DIFFERS")
    ignored = census["ignored_scan"]
    polish._keys(ignored, "ignored_path_count ignored_path_set_digest "
                 "exclusion_taxonomy_digest excluded_cache_build_path_count "
                 "excluded_cache_build_paths_digest inert_ignored_path_count "
                 "inert_ignored_paths_digest excluded_bytes_status")
    for field in ("ignored_path_set_digest", "exclusion_taxonomy_digest",
                  "excluded_cache_build_paths_digest",
                  "inert_ignored_paths_digest"):
        polish._hash(ignored[field])
    _require(ignored["excluded_bytes_status"] == "NOT_VERIFIED",
             "IGNORED_SOURCE_BOUNDARY_DIFFERS")
    files = census["files"]
    _require(type(files) is list
             and len(files) == census["file_count"]
             == value["candidate_source_file_count"]
             and census["total_bytes"] == value["candidate_source_bytes"],
             "SOURCE_FILE_COUNT_DIFFERS")
    seen, total = set(), 0
    for row in files:
        polish._keys(row, "path size sha256 provenance git_mode")
        name = _source_path(row["path"].encode("utf-8"))
        provenance = row["provenance"]
        _require(name not in seen
                 and provenance in {
                     "GIT_TRACKED", "WORKTREE_UNTRACKED_NONIGNORED"
                 }
                 and row["git_mode"] == (
                     row["git_mode"] if provenance == "GIT_TRACKED"
                     else "UNTRACKED_REGULAR"
                 )
                 and (provenance != "GIT_TRACKED"
                      or row["git_mode"] in ("100644", "100755"))
                 and type(row["size"]) is int and row["size"] >= 0,
                 "SOURCE_FILE_RECORD_INVALID")
        polish._hash(row["sha256"])
        seen.add(name); total += row["size"]
    _require(total == census["total_bytes"] and files == sorted(
        files, key=lambda row: row["path"]), "SOURCE_FILE_SET_DIFFERS")
    _require(value["candidate_source_census_digest"] == census["census_digest"]
             and value["worktree_status_digest"] == census["git_status_digest"],
             "CANDIDATE_SOURCE_BINDING_DIFFERS")
    return value


def _source_files(source: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "path": row["path"], "bytes": row["size"], "digest": row["sha256"],
    } for row in source["candidate_source_census"]["files"]]


def _instruction_set_digest(source: dict[str, Any], paths: list[str]) -> str:
    _require(type(paths) is list and bool(paths) and paths == sorted(set(paths)),
             "INSTRUCTION_PATH_SET_INVALID")
    rows = {row["path"]: row for row in _source_files(source)}
    selected = []
    for name in paths:
        _require(type(name) is str and name in rows, "INSTRUCTION_SOURCE_MISSING")
        selected.append(rows[name])
    return polish._digest(canonical_bytes(selected))


def _declared_source_census(item: NamespaceObject, source_id: str) -> list[dict[str, Any]]:
    rows, pending = [], [(item.to_dict(), [])]
    while pending:
        value, path = pending.pop()
        if path:
            row = {"object_id": item.object_id, "object_kind": item.kind.value,
                   "record_digest": item.digest, "path": path,
                   "value_digest": polish._digest(canonical_bytes(value)),
                   "source_unit_id": source_id,
                   "facet_id": polish._digest(canonical_bytes(
                       [source_id, item.object_id, path]))}
            rows.append(row)
        if type(value) is dict:
            pending.extend((child, path + [key])
                           for key, child in sorted(value.items(), reverse=True))
        elif type(value) is list:
            pending.extend((value[index], path + [index])
                           for index in reversed(range(len(value))))
    return sorted(rows, key=lambda row: row["facet_id"])


def _installed_structural_counts() -> tuple[int, int]:
    definitions = application_compiler.installed_rules()["rules"]
    memberships = application_compiler.installed_families(
        [kind.value for kind in ObjectKind])
    return len(definitions), sum(len(row["members"]) for row in memberships)


def core_self_polish_application_id(root: str | Path,
        source_manifest: dict[str, Any] | None = None) -> str:
    """Derive the concrete candidate identity from selected project/source bytes."""
    selected = Path(root).resolve()
    source = (capture_core_self_polish_source(selected) if source_manifest is None
              else _source_manifest(source_manifest))
    indexed = {row["path"]: row for row in _source_files(source)}
    _require("pyproject.toml" in indexed, "PROJECT_IDENTITY_SOURCE_MISSING")
    try:
        raw = (selected / "pyproject.toml").read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise MechanismBindingUnavailable("project identity source unavailable") from exc
    _require(polish._digest(raw) == indexed["pyproject.toml"]["digest"],
             "PROJECT_IDENTITY_SOURCE_DIFFERS")
    project, values = False, {}
    for original in text.splitlines():
        line = original.strip()
        if line == "[project]":
            project = True
            continue
        if project and line.startswith("["):
            break
        if project and "=" in line:
            key, encoded = (part.strip() for part in line.split("=", 1))
            if key in ("name", "version"):
                try:
                    value = json.loads(encoded)
                except (ValueError, TypeError) as exc:
                    raise RequirementRefusal("PROJECT_IDENTITY_INVALID") from exc
                _require(type(value) is str and bool(value.strip()) and len(value) <= 128,
                         "PROJECT_IDENTITY_INVALID")
                values[key] = value
    _require(set(values) == {"name", "version"}, "PROJECT_IDENTITY_INVALID")
    source_digest = polish._digest(canonical_bytes(source))
    identity = (values["name"] + "@" + values["version"] + "+git:" + source["git_head"]
                + "+worktree:" + source_digest)
    _require(len(identity) <= 256, "APPLICATION_ID_INVALID")
    return identity


def prepare_core_self_polish_inputs(root: str | Path, *, application_id: str | None = None,
        instruction_paths: tuple[str, ...] = ("AGENTS.md", "TIME.md"),
        contract_version: str = "2") -> dict[str, Any]:
    """Prepare deterministic inputs; preparation itself grants no gate credit.

    The returned ``selection_digest`` must be retained and selected independently
    by the caller before ``assess_core_self_polish`` can issue a receipt.
    """
    _require(application_id is None or (type(application_id) is str
             and bool(application_id.strip()) and len(application_id) <= 256),
             "APPLICATION_ID_INVALID")
    _require(contract_version in ("1", "2"), "POLISH_CONTRACT_VERSION_UNSUPPORTED")
    source = capture_core_self_polish_source(root)
    source_bytes = canonical_bytes(source)
    mechanism_sources = core_self_polish_source_bindings()
    source_index = {row["path"]: row["digest"] for row in _source_files(source)}
    _require(all(source_index.get(name) == pin for name, pin in mechanism_sources.items()),
             "SELECTED_SOURCE_DOES_NOT_BIND_EXECUTED_MECHANISM")
    mechanism_source_set_digest = polish._digest(canonical_bytes(mechanism_sources))
    observed_application_id = core_self_polish_application_id(root, source)
    _require(application_id is None or application_id == observed_application_id,
             "APPLICATION_ID_DIFFERS_FROM_SELECTED_PROJECT_SOURCE")
    application_id = observed_application_id
    instructions = sorted(instruction_paths)
    instruction_digest = _instruction_set_digest(source, instructions)
    installed_rule_digest = polish._digest(canonical_bytes(
        application_compiler.installed_rules()))
    root_item = NamespaceObject.create("verifier-core-self", "VERIFIER", {
        "application_id": application_id,
        "application_profile_id": application_compiler.STRUCTURAL,
        "source_manifest_digest": polish._digest(source_bytes),
        "instruction_set_digest": instruction_digest,
        "application_compiler_mechanism_digest": application_compiler.mechanism_digest(),
        "mechanism_source_set_digest": mechanism_source_set_digest,
        "installed_rule_set_digest": installed_rule_digest,
    })
    collection = {"schema_version": "verifier-polish-object-collection-1",
                  "objects": [root_item.to_dict()]}
    collection_bytes = canonical_bytes(collection)
    collection_digest = composition_digest([root_item])
    object_policy = object_facets.object_facets_policy(
        trust_roots=["externally-pinned-core-self-polish-selection"])
    typed_policy = typed_facets.typed_facets_policy(
        trust_roots=["externally-pinned-core-self-polish-selection"])
    object_request = object_facets.object_facets_request(root_item, policy=object_policy)
    typed_evidence_bytes = canonical_bytes({
        "schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [root_item.to_dict()],
    })
    typed_request = typed_facets.typed_facets_request(
        object_kind="VERIFIER", subject_id=root_item.object_id,
        object_digest=root_item.digest, collection_digest=collection_digest,
        evidence_ref=polish._digest(typed_evidence_bytes), policy=typed_policy)
    source_unit_id = "selected-verifier-namespace"
    families = application_compiler.installed_families(["VERIFIER"])
    source_scope = {
        "schema_version": application_compiler.SOURCE,
        "scope_id": "core-self-polish-exact-verifier",
        "revision": source["worktree_status_digest"],
        "source_units": [{"unit_id": source_unit_id,
            "language": application_compiler.LANGUAGE,
            "bytes_b64": base64.b64encode(collection_bytes).decode("ascii"),
            "bytes_digest": polish._digest(collection_bytes)}],
        "normative_families": families, "semantic_mappings": [],
        "interaction_generators": application_compiler.installed_interaction_generators(),
        "census_evidence": {"source_member_census_digest": polish._digest(
            canonical_bytes(_declared_source_census(root_item, source_unit_id)))},
    }
    source_scope_bytes = canonical_bytes(source_scope)
    application_selection = {
        "schema_version": application_compiler.SELECTION,
        "application_profile_id": application_compiler.STRUCTURAL,
        "application_profile_version": "1", "root_id": root_item.object_id,
        "semantic_version": application_compiler.SEMANTIC,
        "source_scope_digest": polish._digest(source_scope_bytes),
        "collection_bytes_digest": polish._digest(collection_bytes),
        "collection_digest": collection_digest, "selectors": [],
        "native_intents": [
            {"object_id": root_item.object_id, "coordinate": "OBJECT-1.1",
             "request": object_request, "checker_policy": object_policy},
            {"object_id": root_item.object_id, "coordinate": "VERIFIER-1.1",
             "request": typed_request, "checker_policy": typed_policy},
        ],
    }
    application_selection_bytes = canonical_bytes(application_selection)
    compiler_policy = {
        "schema_version": application_compiler.POLICY,
        "mechanism_digest": application_compiler.mechanism_digest(),
        "source_scope_digest": polish._digest(source_scope_bytes),
        "collection_bytes_digest": polish._digest(collection_bytes),
        "selection_digest": polish._digest(application_selection_bytes),
        "installed_rule_set_digest": installed_rule_digest,
        "normative_family_set_digest": polish._digest(canonical_bytes(
            application_compiler.normative_family_census())),
        "allowed_frontend_digests": [polish._digest(canonical_bytes({
            "language": application_compiler.LANGUAGE,
            "source_pins": application_compiler._PINS}))],
        "admitted_rule_digests": sorted(
            row["rule_digest"] for row in application_compiler.installed_rules()["rules"]),
        "limits": dict(application_compiler.CEILINGS),
    }
    compiler_policy_bytes = canonical_bytes(compiler_policy)
    compiler_report = application_compiler.derive_current_application_requirements(
        source_scope_bytes, collection_bytes, application_selection_bytes,
        expected_compiler_policy_bytes=compiler_policy_bytes)
    compiler_manifest_bytes = canonical_bytes(compiler_report)
    object_certificate = object_facets.build_object_facets_certificate(
        object_request, canonical_bytes(root_item.to_dict()), policy=object_policy)
    typed_certificate = typed_facets.build_typed_facets_certificate(
        typed_request, typed_evidence_bytes, policy=typed_policy)
    certificate_bytes = (object_certificate, typed_certificate)
    certificates = {polish._digest(raw): (raw.decode("utf-8") if contract_version == "1"
        else {"encoding": "utf8", "text": raw.decode("utf-8")})
        for raw in certificate_bytes}
    bundle = {"schema_version": "verifier-polish-bundle-" + contract_version,
              "objects": [root_item.to_dict()], "certificates": certificates}
    if contract_version == "2":
        bundle["evidence_payloads"] = {}
    request = {"schema_version": "verifier-polish-request-" + contract_version,
        "root_id": root_item.object_id, "collection_digest": collection_digest,
        "bundle_digest": "", "requirements": []}
    for tier in range(1, 10):
        row = {"object_id": root_item.object_id, "tier": tier,
               "applicability": "REQUIRED" if tier == 1 else "UNKNOWN",
               "rationale": ("Installed retained structural tier-1 profile"
                             if tier == 1 else "Outside the selected structural profile"),
               "objectives": []}
        request["requirements"].append(row)
    request["requirements"][0]["objectives"] = [
        {"semantic_version": application_compiler.SEMANTIC,
         "coordinate": "OBJECT-1.1", "request": object_request,
         "policy": object_policy, "certificate_digest": polish._digest(object_certificate)},
        {"semantic_version": application_compiler.SEMANTIC,
         "coordinate": "VERIFIER-1.1", "request": typed_request,
         "policy": typed_policy, "certificate_digest": polish._digest(typed_certificate)},
    ]
    if contract_version == "2":
        request["limits"] = dict(CEILINGS)
    bundle_bytes = canonical_bytes(bundle)
    request["bundle_digest"] = polish._digest(bundle_bytes)
    request_bytes = canonical_bytes(request)
    inventory = {"schema_version": INVENTORY_VERSION,
        "semantic_version": application_compiler.SEMANTIC,
        "catalog_digest": requirements_catalog_digest(),
        "root_id": root_item.object_id, "collection_digest": collection_digest,
        "subjects": [{"object_id": root_item.object_id, "object_kind": "VERIFIER",
                      "object_digest": root_item.digest}], "requirements": []}
    for row in request["requirements"]:
        selected_row = {"object_id": row["object_id"], "tier": row["tier"],
            "applicability": row["applicability"],
            "rationale_digest": polish._digest(canonical_bytes(row["rationale"])),
            "objectives": []}
        for objective in row["objectives"]:
            selected_row["objectives"].append({
                "coordinate": objective["coordinate"],
                **registered_objective_binding(objective["semantic_version"],
                    objective["coordinate"], "VERIFIER"),
                "request_digest": polish._digest(canonical_bytes(objective["request"])),
                "policy_digest": polish._digest(canonical_bytes(objective["policy"])),
                "certificate_digest": objective["certificate_digest"],
            })
        inventory["requirements"].append(selected_row)
    inventory_bytes = canonical_bytes(inventory)
    inventory_digest = polish._digest(inventory_bytes)
    native = assess_polish_inventory(bundle_bytes, request_bytes=request_bytes,
        inventory_bytes=inventory_bytes, expected_inventory_digest=inventory_digest,
        contract_version=contract_version)
    definitions, memberships = _installed_structural_counts()
    coordinate = core_application_release.full_gate_coordinate("CORE_SELF_POLISH")
    selection = {"schema_version": CORE_SELF_POLISH_SELECTION,
        **coordinate, "application_id": application_id,
        "application_profile_id": application_compiler.STRUCTURAL,
        "application_profile_version": "1", "root_id": root_item.object_id,
        "root_digest": root_item.digest,
        "source_manifest_digest": polish._digest(source_bytes),
        "source_head": source["git_head"], "source_tree": source["git_tree"],
        "source_worktree_status_digest": source["worktree_status_digest"],
        "instruction_paths": instructions,
        "instruction_set_digest": instruction_digest,
        "source_scope_digest": polish._digest(source_scope_bytes),
        "collection_digest": polish._digest(collection_bytes),
        "application_selection_digest": polish._digest(application_selection_bytes),
        "compiler_policy_digest": polish._digest(compiler_policy_bytes),
        "compiler_manifest_digest": polish._digest(compiler_manifest_bytes),
        "polish_bundle_digest": polish._digest(bundle_bytes),
        "polish_request_digest": polish._digest(request_bytes),
        "polish_inventory_digest": inventory_digest,
        "native_assessment_digest": native["assessment_digest"],
        "mechanism_source_set_digest": mechanism_source_set_digest,
        "requirements_mechanism_digest": mechanism_digest(),
        "self_polish_mechanism_digest": core_self_polish_mechanism_digest(),
        "installed_rule_set_digest": installed_rule_digest,
        "installed_definition_count": definitions,
        "installed_membership_count": memberships,
        "instantiated_obligation_count": 2,
        "contract_version": contract_version}
    selection_bytes = canonical_bytes(selection)
    return {"selection_bytes": selection_bytes,
        "selection_digest": polish._digest(selection_bytes),
        "source_manifest_bytes": source_bytes,
        "source_scope_bytes": source_scope_bytes,
        "collection_bytes": collection_bytes,
        "application_selection_bytes": application_selection_bytes,
        "compiler_policy_bytes": compiler_policy_bytes,
        "compiler_manifest_bytes": compiler_manifest_bytes,
        "polish_bundle_bytes": bundle_bytes,
        "polish_request_bytes": request_bytes,
        "polish_inventory_bytes": inventory_bytes,
        "expected_polish_inventory_digest": inventory_digest,
        "contract_version": contract_version}


def assess_core_self_polish(selection_bytes: bytes, *, expected_selection_digest: str,
        source_manifest_bytes: bytes, source_root: str | Path | None,
        source_scope_bytes: bytes, collection_bytes: bytes,
        application_selection_bytes: bytes, compiler_policy_bytes: bytes,
        compiler_manifest_bytes: bytes, polish_bundle_bytes: bytes,
        polish_request_bytes: bytes, polish_inventory_bytes: bytes,
        expected_polish_inventory_digest: str, contract_version: str = "2",
        cancelled: bool = False) -> dict[str, Any]:
    """Replay the exact selected core self-polish gate and issue only its receipt."""
    report: dict[str, Any] = {"schema_version": CORE_SELF_POLISH_RECEIPT,
        "status": "UNKNOWN", "gate_status": "UNKNOWN", "receipt_status": "NOT_ISSUED",
        "polished": False, "full_application_status": "UNKNOWN",
        "selection_authority": "NOT_ESTABLISHED", "public_checkability": "NOT_ESTABLISHED",
        "human_acceptance": "NOT_ESTABLISHED", "release_authorized": False,
        "claim_boundary": CORE_SELF_POLISH_BOUNDARY, "receipt": None}
    try:
        _require(type(cancelled) is bool, "CANCEL_FLAG_INVALID")
        polish._hash(expected_selection_digest)
        _require(type(selection_bytes) is bytes
                 and polish._digest(selection_bytes) == expected_selection_digest,
                 "EXTERNAL_SELF_POLISH_SELECTION_DIFFERS")
        selection = polish._load(selection_bytes, MAX_INVENTORY_BYTES)
        polish._keys(selection, "schema_version semantic_version objective proposition_digest "
            "application_id application_profile_id application_profile_version root_id root_digest "
            "source_manifest_digest source_head source_tree source_worktree_status_digest "
            "instruction_paths instruction_set_digest source_scope_digest collection_digest "
            "application_selection_digest compiler_policy_digest compiler_manifest_digest "
            "polish_bundle_digest polish_request_digest polish_inventory_digest "
            "native_assessment_digest requirements_mechanism_digest self_polish_mechanism_digest "
            "mechanism_source_set_digest "
            "installed_rule_set_digest installed_definition_count installed_membership_count "
            "instantiated_obligation_count contract_version")
        coordinate = core_application_release.full_gate_coordinate("CORE_SELF_POLISH")
        _require(selection["schema_version"] == CORE_SELF_POLISH_SELECTION
                 and all(selection[key] == value for key, value in coordinate.items()),
                 "CORE_SELF_POLISH_COORDINATE_DIFFERS")
        _require(selection["application_profile_id"] == application_compiler.STRUCTURAL
                 and selection["application_profile_version"] == "1"
                 and selection["contract_version"] == contract_version,
                 "CORE_SELF_POLISH_PROFILE_DIFFERS")
        _require(type(selection["application_id"]) is str
                 and 0 < len(selection["application_id"].strip()) <= 256,
                 "APPLICATION_ID_INVALID")
        for field in ("root_digest", "source_manifest_digest",
                "source_worktree_status_digest", "instruction_set_digest",
                "source_scope_digest", "collection_digest", "application_selection_digest",
                "compiler_policy_digest", "compiler_manifest_digest", "polish_bundle_digest",
                "polish_request_digest", "polish_inventory_digest", "native_assessment_digest",
                "mechanism_source_set_digest",
                "requirements_mechanism_digest", "self_polish_mechanism_digest",
                "installed_rule_set_digest"):
            polish._hash(selection[field])
        if cancelled:
            report["reason"] = "SELF_POLISH_REPLAY_CANCELLED"
            raise MechanismBindingUnavailable("self polish replay cancelled")
        source = _source_manifest(polish._load(source_manifest_bytes, MAX_INVENTORY_BYTES))
        _require(selection["source_manifest_digest"] == polish._digest(source_manifest_bytes)
                 and selection["source_head"] == source["git_head"]
                 and selection["source_tree"] == source["git_tree"]
                 and selection["source_worktree_status_digest"] == source["worktree_status_digest"],
                 "SOURCE_SELECTION_DIFFERS")
        if source_root is None:
            report["reason"] = "SOURCE_REPLAY_ROOT_UNAVAILABLE"
            raise MechanismBindingUnavailable("source replay root unavailable")
        observed_source = capture_core_self_polish_source(source_root)
        _require(canonical_bytes(observed_source) == source_manifest_bytes,
                 "SOURCE_STATE_DIFFERS")
        mechanism_sources = core_self_polish_source_bindings()
        source_index = {row["path"]: row["digest"] for row in _source_files(source)}
        _require(selection["mechanism_source_set_digest"]
                    == polish._digest(canonical_bytes(mechanism_sources))
                 and all(source_index.get(name) == pin
                         for name, pin in mechanism_sources.items()),
                 "SELECTED_SOURCE_DOES_NOT_BIND_EXECUTED_MECHANISM")
        _require(selection["instruction_set_digest"] == _instruction_set_digest(
            source, selection["instruction_paths"]), "INSTRUCTION_SET_DIFFERS")
        inputs = {"source_scope_digest": source_scope_bytes,
            "collection_digest": collection_bytes,
            "application_selection_digest": application_selection_bytes,
            "compiler_policy_digest": compiler_policy_bytes,
            "compiler_manifest_digest": compiler_manifest_bytes,
            "polish_bundle_digest": polish_bundle_bytes,
            "polish_request_digest": polish_request_bytes,
            "polish_inventory_digest": polish_inventory_bytes}
        _require(all(selection[key] == polish._digest(raw) for key, raw in inputs.items()),
                 "SELF_POLISH_INPUT_SELECTION_DIFFERS")
        _require(selection["polish_inventory_digest"] == expected_polish_inventory_digest,
                 "POLISH_INVENTORY_EXTERNAL_PIN_DIFFERS")
        _require(selection["requirements_mechanism_digest"] == mechanism_digest()
                 and selection["self_polish_mechanism_digest"] == core_self_polish_mechanism_digest(),
                 "SELF_POLISH_MECHANISM_DIFFERS")
        definitions, memberships = _installed_structural_counts()
        _require(selection["installed_definition_count"] == definitions == 27
                 and selection["installed_membership_count"] == memberships == 52
                 and selection["instantiated_obligation_count"] == 2,
                 "STRUCTURAL_DENOMINATOR_DIFFERS")
        installed_rule_digest = polish._digest(canonical_bytes(
            application_compiler.installed_rules()))
        _require(selection["installed_rule_set_digest"] == installed_rule_digest,
                 "INSTALLED_RULE_SET_DIFFERS")
        compiled = application_compiler.derive_current_application_requirements(
            source_scope_bytes, collection_bytes, application_selection_bytes,
            expected_compiler_policy_bytes=compiler_policy_bytes)
        _require(canonical_bytes(compiled) == compiler_manifest_bytes,
                 "APPLICATION_COMPILER_REPLAY_DIFFERS")
        compiler_replay = application_compiler.recheck_current_application_requirements(
            compiler_manifest_bytes,
            expected_mechanism_digest=compiled["mechanism_digest"],
            expected_manifest_digest=compiled["manifest_digest"],
            source_scope_bytes=source_scope_bytes, collection_bytes=collection_bytes,
            selection_bytes=application_selection_bytes,
            expected_compiler_policy_bytes=compiler_policy_bytes)
        _require(compiled["status"] == "PASS"
                 and compiled["scope_kind"] == application_compiler.STRUCTURAL
                 and compiled["closure_status"] == "CLOSED_FOR_EXACT_SELECTED_FINITE_SCOPE"
                 and compiled["full_application_status"] == "UNKNOWN"
                 and compiled["polished"] is False
                 and compiler_replay["replay_status"] == "REPRODUCED",
                 "APPLICATION_COMPILER_SCOPE_NOT_CLOSED")
        collection = polish._load(collection_bytes, MAX_INVENTORY_BYTES)
        polish._keys(collection, "schema_version objects")
        _require(collection["schema_version"] == "verifier-polish-object-collection-1"
                 and type(collection["objects"]) is list and len(collection["objects"]) == 1,
                 "SELF_POLISH_COLLECTION_DIFFERS")
        item = NamespaceObject.create(**collection["objects"][0])
        _require(item.kind.value == "VERIFIER" and item.object_id == selection["root_id"]
                 and item.digest == selection["root_digest"], "SELF_POLISH_ROOT_DIFFERS")
        payload = item.payload
        _require(payload.get("application_id") == selection["application_id"]
                 and payload.get("application_profile_id") == application_compiler.STRUCTURAL
                 and payload.get("source_manifest_digest") == selection["source_manifest_digest"]
                 and payload.get("instruction_set_digest") == selection["instruction_set_digest"]
                 and payload.get("application_compiler_mechanism_digest")
                    == application_compiler.mechanism_digest()
                 and payload.get("mechanism_source_set_digest")
                    == selection["mechanism_source_set_digest"]
                 and payload.get("installed_rule_set_digest") == installed_rule_digest,
                 "SELF_POLISH_ROOT_PAYLOAD_DIFFERS")
        obligations = compiled["required_objectives"]
        _require(len(obligations) == 2
                 and {row["coordinate"] for row in obligations}
                    == {"OBJECT-1.1", "VERIFIER-1.1"}
                 and all(row["object_id"] == item.object_id
                         and row["binding_status"] == "PASS" for row in obligations),
                 "INSTANTIATED_OBLIGATION_SET_DIFFERS")
        native = assess_polish_inventory(polish_bundle_bytes,
            request_bytes=polish_request_bytes, inventory_bytes=polish_inventory_bytes,
            expected_inventory_digest=expected_polish_inventory_digest,
            contract_version=contract_version)
        _require(native["assessment_digest"] == selection["native_assessment_digest"]
                 and native["declared_coverage"] == "PASS"
                 and native["status"] == "UNKNOWN"
                 and native["selected_objective_count"] == 2
                 and native["open_required_slots"] == []
                 and native["unregistered_objectives"] == []
                 and native["mechanism_binding_gaps"] == []
                 and len(native["native_assessment"]["objectives"]) == 2
                 and all(row["status"] == "PASS"
                         for row in native["native_assessment"]["objectives"]),
                 "SELECTED_NATIVE_REPLAY_NOT_CLOSED")
        receipt = {"schema_version": CORE_SELF_POLISH_RECEIPT,
            **coordinate, "status": "PASS", "gate": "CORE_SELF_POLISH",
            "application_id": selection["application_id"],
            "application_profile_id": application_compiler.STRUCTURAL,
            "root_id": item.object_id, "root_digest": item.digest,
            "source_manifest_digest": selection["source_manifest_digest"],
            "source_head": source["git_head"], "source_tree": source["git_tree"],
            "source_worktree_status_digest": source["worktree_status_digest"],
            "worktree_clean": source["worktree_clean"],
            "selection_digest": expected_selection_digest,
            "compiler_manifest_digest": selection["compiler_manifest_digest"],
            "native_assessment_digest": native["assessment_digest"],
            "self_polish_mechanism_digest": selection["self_polish_mechanism_digest"],
            "mechanism_source_set_digest": selection["mechanism_source_set_digest"],
            "installed_definition_count": definitions,
            "installed_membership_count": memberships,
            "instantiated_obligation_count": 2,
            "selected_native_objective_status": "PASS",
            "application_compiler_replay": "REPRODUCED",
            "full_application_status": "UNKNOWN", "polished": False,
            "selection_authority": "NOT_ESTABLISHED",
            "public_checkability": "NOT_ESTABLISHED",
            "human_acceptance": "NOT_ESTABLISHED",
            "release_authorized": False, "claim_boundary": CORE_SELF_POLISH_BOUNDARY,
            "invalidated_by": ["source-head-tree-worktree-or-file-byte-change",
                "instruction-byte-or-path-change", "selection-or-input-digest-change",
                "installed-rule-compiler-native-route-or-mechanism-change"]}
        receipt["receipt_digest"] = polish._digest(canonical_bytes(receipt))
        report.update(status="PASS", gate_status="PASS", receipt_status="ISSUED",
            source_replay="REPRODUCED", application_compiler_replay="REPRODUCED",
            selected_native_replay="PASS", installed_definition_count=definitions,
            installed_membership_count=memberships, instantiated_obligation_count=2,
            selection_digest=expected_selection_digest, receipt=receipt)
    except MechanismBindingUnavailable:
        report.setdefault("reason", "SELF_POLISH_MECHANISM_OR_SOURCE_UNAVAILABLE")
    except RequirementRefusal as exc:
        report.update(status="FAIL", gate_status="FAIL", reason=str(exc))
    except CapacityExceeded as exc:
        report.update(reason="RESOURCE_LIMIT_EXCEEDED",
                      exhausted_resource=exc.resource)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError,
            RecursionError, OverflowError):
        report.update(status="FAIL", gate_status="FAIL",
                      reason="INVALID_OR_SUBSTITUTED_CORE_SELF_POLISH_INPUT")
    report["assessment_digest"] = polish._digest(canonical_bytes(report))
    return report


def recheck_core_self_polish_receipt(assessment_bytes: bytes, *,
        expected_assessment_digest: str, expected_receipt_digest: str,
        **assessment_inputs: Any) -> dict[str, Any]:
    """Reproduce a retained receipt against current exact source and mechanisms."""
    replay = {"schema_version": CORE_SELF_POLISH_REPLAY, "status": "FAIL",
              "replay_status": "REJECTED", "polished": False,
              "full_application_status": "UNKNOWN"}
    try:
        polish._hash(expected_assessment_digest); polish._hash(expected_receipt_digest)
        stored = polish._load(assessment_bytes, MAX_INVENTORY_BYTES)
        _require(stored.get("schema_version") == CORE_SELF_POLISH_RECEIPT
                 and stored.get("assessment_digest") == expected_assessment_digest
                 and polish._digest(canonical_bytes({key: value for key, value in stored.items()
                    if key != "assessment_digest"})) == expected_assessment_digest,
                 "STORED_SELF_POLISH_ASSESSMENT_DIFFERS")
        receipt = stored.get("receipt")
        _require(type(receipt) is dict and receipt.get("receipt_digest") == expected_receipt_digest
                 and polish._digest(canonical_bytes({key: value for key, value in receipt.items()
                    if key != "receipt_digest"})) == expected_receipt_digest,
                 "STORED_SELF_POLISH_RECEIPT_DIFFERS")
        current = assess_core_self_polish(**assessment_inputs)
        if current["status"] == "UNKNOWN":
            replay.update(status="UNKNOWN", replay_status="UNAVAILABLE",
                          reason=current.get("reason", "SELF_POLISH_REPLAY_UNAVAILABLE"))
        elif (current["status"] == "PASS" and current == stored
              and current["receipt"]["receipt_digest"] == expected_receipt_digest):
            replay.update(status="PASS", replay_status="REPRODUCED",
                          assessment_digest=expected_assessment_digest,
                          receipt_digest=expected_receipt_digest,
                          source_replay="REPRODUCED")
    except RequirementRefusal as exc:
        replay["reason"] = str(exc)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError,
            RecursionError, OverflowError):
        replay["reason"] = "INVALID_OR_SUBSTITUTED_CORE_SELF_POLISH_REPLAY"
    replay["replay_digest"] = polish._digest(canonical_bytes(replay))
    return replay


def _indexed_rows(rows: Any, subjects: dict[str, Any], *, inventory: bool, cap: int) -> dict[tuple[str, int], dict[str, Any]]:
    _require(type(rows) is list and len(rows) <= cap, "REQUIREMENT_ROW_BOUND_INVALID")
    result = {}
    for row in rows:
        polish._keys(row, "object_id tier applicability objectives " + ("rationale_digest" if inventory else "rationale"))
        object_id, tier = polish._text(row["object_id"]), row["tier"]
        _require(object_id in subjects and type(tier) is int and 1 <= tier <= 9, "REQUIREMENT_SUBJECT_OR_TIER_DIFFERS")
        _require((object_id, tier) not in result, "DUPLICATE_REQUIREMENT_ROW")
        _require(row["applicability"] in ("REQUIRED", "NOT_APPLICABLE", "UNKNOWN"), "APPLICABILITY_INVALID")
        _require(type(row["objectives"]) is list, "OBJECTIVE_LIST_REQUIRED")
        _require(row["applicability"] == "REQUIRED" or not row["objectives"], "NON_REQUIRED_ROW_HAS_OBJECTIVES")
        if inventory:
            polish._hash(row["rationale_digest"])
        else:
            polish._text(row["rationale"])
        result[object_id, tier] = row
    return result


def _preflight(bundle: dict[str, Any], request: dict[str, Any], inventory: dict[str, Any], version: str,
               budget: Budget | None = None) -> dict[str, Any]:
    polish._keys(inventory, "schema_version semantic_version catalog_digest root_id collection_digest subjects requirements")
    _require(inventory["schema_version"] == INVENTORY_VERSION, "INVENTORY_VERSION_UNSUPPORTED")
    _require(polish._hash(inventory["catalog_digest"]) == requirements_catalog_digest(), "REGISTERED_CATALOG_DIFFERS")
    semantic = polish._text(inventory["semantic_version"])
    _require(semantic in {row["semantic_version"] for row in current_object_route_catalog()}, "SEMANTIC_VERSION_UNSUPPORTED")
    polish._keys(request, "schema_version root_id collection_digest bundle_digest requirements" + (" limits" if version == "2" else ""))
    polish._keys(bundle, "schema_version objects certificates" + (" evidence_payloads" if version == "2" else ""))
    _require(request["schema_version"] == "verifier-polish-request-" + version
        and bundle["schema_version"] == "verifier-polish-bundle-" + version, "POLISH_CONTRACT_VERSION_DIFFERS")
    _require(inventory["root_id"] == request["root_id"]
        and polish._hash(inventory["collection_digest"]) == request["collection_digest"], "SELECTED_COLLECTION_DIFFERS")
    object_cap = polish.MAX_OBJECTS if version == "1" else CEILINGS["objects"]
    objective_cap = polish.MAX_OBJECTIVES if version == "1" else CEILINGS["objectives"]
    _require(type(bundle["objects"]) is list and 1 <= len(bundle["objects"]) <= object_cap, "OBJECT_BOUND_INVALID")
    _require(type(inventory["subjects"]) is list
        and len(inventory["subjects"]) == len(bundle["objects"]), "INVENTORY_SUBJECT_SET_DIFFERS")
    if budget is not None:
        # Charge both selected lists before constructing any namespace object.
        # The maximum is the admitted obligation count, not a cumulative charge
        # for reading its inventory and submitted-request representations twice.
        budget.charge("objects", len(bundle["objects"]))
        rows = (inventory["requirements"], request["requirements"])
        _require(all(type(values) is list for values in rows), "REQUIREMENT_ROW_BOUND_INVALID")
        budget.charge("requirements", max(len(values) for values in rows))
        counts = []
        for values in rows:
            _require(all(type(row) is dict and type(row.get("objectives")) is list for row in values),
                     "OBJECTIVE_LIST_REQUIRED")
            counts.append(sum(len(row["objectives"]) for row in values))
        budget.charge("objectives", max(counts))
    objects = {}
    for record in bundle["objects"]:
        polish._keys(record, "object_id kind payload operands")
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        _require(item.object_id not in objects, "DUPLICATE_SUBJECT")
        objects[item.object_id] = item
    subjects = {}
    for row in inventory["subjects"]:
        polish._keys(row, "object_id object_kind object_digest")
        object_id = polish._text(row["object_id"])
        _require(object_id not in subjects, "DUPLICATE_SUBJECT")
        _require(object_id in objects, "INVENTORY_SUBJECT_SET_DIFFERS")
        _require(row["object_kind"] in {kind.value for kind in ObjectKind}
            and row["object_kind"] == objects[object_id].kind.value
            and polish._hash(row["object_digest"]) == objects[object_id].digest, "INVENTORY_SUBJECT_BINDING_DIFFERS")
        subjects[object_id] = row
    expected = _indexed_rows(inventory["requirements"], subjects, inventory=True, cap=object_cap * 9)
    supplied = _indexed_rows(request["requirements"], subjects, inventory=False, cap=object_cap * 9)
    full = {(key, tier) for key in subjects for tier in range(1, 10)}
    _require(set(expected) == full, "INVENTORY_TIER_OMISSION")
    _require(set(supplied) == full, "REQUEST_TIER_SET_DIFFERS")
    _require(sum(len(row["objectives"]) for row in expected.values()) <= objective_cap
        and sum(len(row["objectives"]) for row in supplied.values()) <= objective_cap, "OBJECTIVE_BOUND_INVALID")
    gaps, binding_gaps, open_slots, count = [], [], [], 0
    bindings = {}
    catalog_keys = {(row["semantic_version"], row["objective"]) for row in current_object_route_catalog()}
    for key in sorted(full):
        wanted, actual = expected[key], supplied[key]
        _require(wanted["applicability"] == actual["applicability"]
            and wanted["rationale_digest"] == polish._digest(canonical_bytes(actual["rationale"])), "APPLICABILITY_DECLARATION_DIFFERS")
        if wanted["applicability"] == "REQUIRED" and not wanted["objectives"]:
            open_slots.append({"object_id": key[0], "tier": key[1]})
        selected = {}
        for objective in actual["objectives"]:
            polish._keys(objective, "semantic_version coordinate request policy certificate_digest")
            _require(objective["semantic_version"] == semantic, "SEMANTIC_VERSION_DIFFERS")
            coordinate = polish._text(objective["coordinate"])
            _require(coordinate not in selected, "DUPLICATE_OBJECTIVE")
            selected[coordinate] = objective
        required = {}
        for objective in wanted["objectives"]:
            polish._keys(objective, "coordinate mechanism_id mechanism_digest proposition_digest request_digest policy_digest certificate_digest")
            coordinate = polish._text(objective["coordinate"])
            _require(coordinate not in required, "DUPLICATE_OBJECTIVE")
            address = ObjectCoordinate.parse(coordinate)
            _require(address.tier.value == key[1] and address.object_kind.value in ("OBJECT", subjects[key[0]]["object_kind"]), "OBJECTIVE_KIND_OR_TIER_DIFFERS")
            polish._text(objective["mechanism_id"])
            for field in ("mechanism_digest", "proposition_digest", "request_digest", "policy_digest", "certificate_digest"):
                polish._hash(objective[field])
            required[coordinate] = objective
        _require(set(required) == set(selected), "REQUEST_OBJECTIVE_SET_DIFFERS")
        for coordinate, objective in required.items():
            supplied_objective = selected[coordinate]
            _require(objective["request_digest"] == polish._digest(canonical_bytes(supplied_objective["request"]))
                and objective["policy_digest"] == polish._digest(canonical_bytes(supplied_objective["policy"]))
                and objective["certificate_digest"] == supplied_objective["certificate_digest"], "OBJECTIVE_EVIDENCE_SELECTION_DIFFERS")
            count += 1
            if (semantic, coordinate) not in catalog_keys:
                gaps.append({"object_id": key[0], "tier": key[1], "coordinate": coordinate, "reason": "UNREGISTERED_OBJECTIVE"})
                continue
            cache_key = (semantic, coordinate, subjects[key[0]]["object_kind"])
            try:
                if cache_key not in bindings:
                    bindings[cache_key] = registered_objective_binding(*cache_key)
            except CurrentObjectRouteRefusal as exc:
                raise RequirementRefusal("REGISTERED_OBJECTIVE_KIND_DIFFERS") from exc
            except MechanismBindingUnavailable:
                binding_gaps.append({"object_id": key[0], "tier": key[1], "coordinate": coordinate,
                    "reason": "NATIVE_MECHANISM_BINDING_UNAVAILABLE"})
                continue
            _require(all(objective[field] == value for field, value in bindings[cache_key].items()), "REGISTERED_MECHANISM_OR_PROPOSITION_DIFFERS")
    return {"selected_objective_count": count, "unregistered_objectives": gaps,
        "mechanism_binding_gaps": binding_gaps, "open_required_slots": open_slots}


def assess_polish_inventory(bundle_bytes: bytes, *, request_bytes: bytes, inventory_bytes: bytes,
                           expected_inventory_digest: str, contract_version: str = "1") -> dict[str, Any]:
    """Compare independent obligations before delegating actual native replay.

    The caller must select the expected inventory digest independently. Neither
    this function nor the command-line caller may infer it from a submitted file.
    """
    report: dict[str, Any] = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "declared_coverage": "UNKNOWN", "polished": False,
        "objective_inventory_closure": "NOT_ESTABLISHED",
        "inventory_authentication": "NOT_ESTABLISHED", "claim_boundary": BOUNDARY,
        "mechanism_digest": mechanism_digest()}
    budget = None
    try:
        _require(type(contract_version) is str and contract_version in ("1", "2"), "POLISH_CONTRACT_VERSION_UNSUPPORTED")
        polish._hash(expected_inventory_digest)
        inventory = polish._load(inventory_bytes, MAX_INVENTORY_BYTES)
        _require(polish._digest(inventory_bytes) == expected_inventory_digest, "EXTERNAL_INVENTORY_DIGEST_DIFFERS")
        request = polish._load(request_bytes, polish.MAX_REQUEST_BYTES if contract_version == "1" else CEILINGS["request_bytes"])
        _require(type(bundle_bytes) is bytes, "IMMUTABLE_BUNDLE_BYTES_REQUIRED")
        if contract_version == "2":
            polish._keys(request, "schema_version root_id collection_digest bundle_digest requirements limits")
            _require(request["schema_version"] == "verifier-polish-request-2", "POLISH_CONTRACT_VERSION_DIFFERS")
            budget = Budget(request["limits"])
            budget.charge("request_bytes", len(request_bytes))
            budget.charge("bundle_bytes", len(bundle_bytes))
        _require(polish._hash(request.get("bundle_digest")) == polish._digest(bundle_bytes), "SELECTED_BUNDLE_DIFFERS")
        bundle = polish._load(bundle_bytes, polish.MAX_BUNDLE_BYTES if contract_version == "1" else CEILINGS["bundle_bytes"])
        compared = _preflight(bundle, request, inventory, contract_version, budget)
        # Reuse native subject binding, finite dependency composition, certificate
        # byte checks, version-2 capacity and objective-specific replay unchanged.
        native = polish.assess_polish(bundle_bytes, request_bytes=request_bytes, contract_version=contract_version)
        _require(native.get("polished") is False and native.get("objective_inventory_closure") == "NOT_ESTABLISHED",
                 "NATIVE_POLISH_BOUNDARY_CHANGED")
        _require(native.get("status") in ("FAIL", "UNKNOWN"), "NATIVE_POLISH_STATUS_UNSUPPORTED")
        results = native.get("objectives", [])
        covered = (compared["selected_objective_count"] > 0
            and not compared["unregistered_objectives"]
            and not compared["mechanism_binding_gaps"]
            and len(results) == compared["selected_objective_count"]
            and all(row.get("status") == "PASS" for row in results))
        report.update(compared, native_assessment=native,
            inventory_digest=expected_inventory_digest,
            request_digest=polish._digest(request_bytes), bundle_digest=polish._digest(bundle_bytes),
            declared_coverage="FAIL" if native["status"] == "FAIL" else "PASS" if covered else "UNKNOWN",
            status=native["status"])
    except CapacityExceeded as exc:
        report.update(status="UNKNOWN", declared_coverage="UNKNOWN", reason="RESOURCE_LIMIT_EXCEEDED",
            exhausted_resource=exc.resource, resource_stage="REQUIREMENTS_PREFLIGHT")
    except RequirementRefusal as exc:
        report.update(status="FAIL", declared_coverage="FAIL", reason=str(exc))
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        report.update(status="FAIL", declared_coverage="FAIL", reason="INVALID_REQUIREMENTS_OR_SELECTION")
    report["assessment_digest"] = polish._digest(canonical_bytes(report))
    return report


__all__ = [
    "MAX_INVENTORY_BYTES", "assess_polish_inventory", "requirements_catalog_digest",
    "registered_objective_binding", "mechanism_digest",
    "CORE_SELF_POLISH_SELECTION", "CORE_SELF_POLISH_SOURCE",
    "CORE_SELF_POLISH_RECEIPT", "CORE_SELF_POLISH_REPLAY",
    "CORE_SELF_POLISH_MECHANISM_ID", "capture_core_self_polish_source",
    "core_self_polish_source_bindings", "core_self_polish_application_id",
    "prepare_core_self_polish_inputs",
    "assess_core_self_polish",
    "recheck_core_self_polish_receipt", "core_self_polish_mechanism_digest",
]
