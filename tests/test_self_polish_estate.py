from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import public_cli
from verifier.runtime import self_polish_estate as estate_module
from verifier.runtime.self_polish_estate import (
    EstateError,
    REQUIRED_CATEGORIES,
    applicability_ledger_template,
    build_candidate_estate,
    canonical_bytes,
    validate_applicability_ledger,
    value_digest,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def candidate_estate() -> dict[str, object]:
    patch = pytest.MonkeyPatch()
    tracked = estate_module._git_tracked_paths(ROOT)
    untracked = estate_module._git_untracked_paths(ROOT)
    ignored = estate_module._git_ignored_paths(ROOT)
    modes, index_digest = estate_module._git_index_state(ROOT, tracked)
    status_digest = estate_module._git_status_digest(ROOT)
    coordinate = estate_module._git_coordinate(ROOT)
    patch.setattr(estate_module, "_git_coordinate", lambda root: dict(coordinate))
    patch.setattr(estate_module, "_git_tracked_paths", lambda root: tracked)
    patch.setattr(estate_module, "_git_untracked_paths", lambda root: untracked)
    patch.setattr(estate_module, "_git_ignored_paths", lambda root: ignored)
    patch.setattr(
        estate_module, "_git_index_state",
        lambda root, selected: (dict(modes), index_digest),
    )
    patch.setattr(
        estate_module, "_git_status_digest", lambda root: status_digest,
    )
    try:
        return build_candidate_estate(
            ROOT,
            expected_repository=coordinate["repository"],
            expected_revision=coordinate["revision"],
        )
    finally:
        patch.undo()


def _refresh_ledger_digest(ledger: dict[str, object]) -> bytes:
    body = {key: value for key, value in ledger.items() if key != "ledger_digest"}
    ledger["ledger_digest"] = value_digest(body)
    return canonical_bytes(ledger)


def test_candidate_estate_is_exact_source_bound_and_semantically_fail_closed(
    candidate_estate: dict[str, object],
) -> None:
    assert candidate_estate["mechanical_census_status"] == "PASS"
    assert candidate_estate["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert candidate_estate["full_estate_closure"] == "NOT_ESTABLISHED"
    assert candidate_estate["polished"] is False
    assert candidate_estate["release_authorized"] is False
    assert candidate_estate["pre_source_census"] \
        == candidate_estate["post_source_census"]
    assert candidate_estate["source_coordinate"][
        "candidate_source_census_digest"
    ] == candidate_estate["pre_source_census"]["census_digest"]

    candidates = candidate_estate["candidates"]
    identifiers = [row["candidate_id"] for row in candidates]
    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    assert {row["category"] for row in candidates} == set(REQUIRED_CATEGORIES)
    assert all(row["applicability_status"] == "UNKNOWN" for row in candidates)
    assert all(row["authority_status"] == "NOT_ESTABLISHED" for row in candidates)
    assert all(row["evidence_status"] == "NOT_ESTABLISHED" for row in candidates)
    assert all(row["semantic_status"] == "NOT_ESTABLISHED" for row in candidates)


def test_installed_inventory_and_structural_crosswalk_are_exact(
    candidate_estate: dict[str, object],
) -> None:
    counts = {
        summary["category"]: summary["candidate_count"]
        for summary in candidate_estate["category_summaries"]
    }
    assert counts["installed_cell"] == 234
    assert counts["installed_route"] == 408
    assert counts["installed_mechanism"] == 97
    assert counts["structural_family"] == 26
    assert counts["structural_membership"] == 52
    assert counts["structural_route_crosswalk"] == 70
    assert candidate_estate["structural_route_crosswalk"] == {
        **candidate_estate["structural_route_crosswalk"],
        "status": "NOT_ESTABLISHED",
        "structural_membership_count": 52,
        "route_tier1_membership_count": 45,
        "shared_identity_count": 27,
        "structural_only_identity_count": 25,
        "route_only_identity_count": 18,
    }


def test_every_declared_surface_category_has_deterministic_rows(
    candidate_estate: dict[str, object],
) -> None:
    summaries = candidate_estate["category_summaries"]
    assert [row["category"] for row in summaries] == list(REQUIRED_CATEGORIES)
    assert all(row["mechanical_status"] == "PASS" for row in summaries)
    assert all(row["semantic_status"] == "NOT_ESTABLISHED" for row in summaries)
    assert all(row["candidate_count"] > 0 for row in summaries)
    assert all(row["candidate_digest"].startswith("sha256:") for row in summaries)
    unknowns = [
        row for row in candidate_estate["candidates"]
        if row["category"] == "unresolved_surface"
    ]
    assert len(unknowns) == 3
    assert {row["metadata"]["surface_id"] for row in unknowns} == {
        "external-plugin-estate",
        "generated-build-backend-estate",
        "runtime-environment-estate",
    }
    assert all(row["metadata"]["enumeration_status"] == "UNKNOWN" for row in unknowns)


def test_python_callable_census_includes_methods_and_nested_functions(
    candidate_estate: dict[str, object],
) -> None:
    functions = [
        row for row in candidate_estate["candidates"]
        if row["category"] == "python_function"
    ]
    assert any(
        row["candidate_type"] == "CLASS_METHOD_CANDIDATE_FUNCTION"
        and "." in row["metadata"]["qualname"]
        for row in functions
    )
    assert any(
        row["candidate_type"] == "NESTED_CANDIDATE_FUNCTION"
        and ".<locals>." in row["metadata"]["qualname"]
        for row in functions
    )
    assert all(row["metadata"]["qualname"] for row in functions)


def test_runtime_providers_are_byte_bound_to_selected_root(
    candidate_estate: dict[str, object], monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bound = estate_module._runtime_source_binding(
        ROOT, candidate_estate["pre_source_census"]
    )
    assert bound["status"] == "PASS"
    assert bound["module_count"] >= 6
    snapshot = deepcopy(candidate_estate["pre_source_census"])
    provider = next(
        row for row in snapshot["files"]
        if row["path"] == "src/verifier/runtime/public_cli.py"
    )
    provider["sha256"] = "sha256:" + "0" * 64
    with pytest.raises(
        EstateError, match="^RUNTIME_PROVIDER_SOURCE_BYTES_DIFFER$"
    ):
        estate_module._runtime_source_binding(ROOT, snapshot)

    monkeypatch.setattr(estate_module.public_cli, "__file__", __file__)
    with pytest.raises(
        EstateError, match="^RUNTIME_PROVIDER_SOURCE_BYTES_DIFFER$"
    ):
        estate_module._runtime_source_binding(
            ROOT, candidate_estate["pre_source_census"]
        )

    installed_copy = tmp_path / "public_cli.py"
    installed_copy.write_bytes((
        ROOT / "src" / "verifier" / "runtime" / "public_cli.py"
    ).read_bytes())
    monkeypatch.setattr(estate_module.public_cli, "__file__", installed_copy)
    rebound = estate_module._runtime_source_binding(
        ROOT, candidate_estate["pre_source_census"]
    )
    assert rebound["status"] == "PASS"


def test_all_unknown_applicability_template_validates_without_closure(
    candidate_estate: dict[str, object],
) -> None:
    ledger = applicability_ledger_template(candidate_estate)
    result = validate_applicability_ledger(
        candidate_estate,
        canonical_bytes(ledger),
        expected_ledger_digest=ledger["ledger_digest"],
    )
    assert result["mechanical_validation_status"] == "PASS"
    assert result["caller_declared_pass_count"] == 0
    assert result["caller_pass_authentication"] == "NOT_ESTABLISHED"
    assert result["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert result["full_estate_closure"] == "NOT_ESTABLISHED"


def test_caller_authored_pass_and_digests_cannot_authenticate_themselves(
    candidate_estate: dict[str, object],
) -> None:
    ledger = applicability_ledger_template(candidate_estate)
    fake = "sha256:" + "a" * 64
    for row in ledger["rows"]:
        row.update({
            "applicability_status": "APPLICABLE",
            "authority_status": "PASS",
            "evidence_status": "PASS",
            "authority_digest": fake,
            "evidence_digest": fake,
            "justification": "Caller declaration only.",
        })
    raw = _refresh_ledger_digest(ledger)
    result = validate_applicability_ledger(
        candidate_estate, raw,
        expected_ledger_digest=ledger["ledger_digest"],
    )
    assert result["caller_declared_pass_count"] == candidate_estate["candidate_count"]
    assert result["caller_pass_authentication"] == "NOT_ESTABLISHED"
    assert result["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert result["full_estate_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("missing", "APPLICABILITY_LEDGER_DENOMINATOR_DIFFERS"),
        ("duplicate", "APPLICABILITY_LEDGER_ID_SET_DIFFERS"),
        ("extra", "APPLICABILITY_LEDGER_DENOMINATOR_DIFFERS"),
        ("substituted", "APPLICABILITY_LEDGER_CANDIDATE_SUBSTITUTED"),
        ("stale", "APPLICABILITY_LEDGER_SOURCE_OR_UNIVERSE_DIFFERS"),
    ),
)
def test_applicability_ledger_rejects_incomplete_duplicate_extra_substituted_and_stale(
    candidate_estate: dict[str, object], mutation: str, error: str,
) -> None:
    ledger = applicability_ledger_template(candidate_estate)
    if mutation == "missing":
        ledger["rows"].pop()
    elif mutation == "duplicate":
        ledger["rows"][-1] = deepcopy(ledger["rows"][0])
    elif mutation == "extra":
        ledger["rows"].append({**deepcopy(ledger["rows"][0]),
                               "candidate_id": "candidate-not-in-universe"})
    elif mutation == "substituted":
        ledger["rows"][0]["candidate_digest"] = "sha256:" + "b" * 64
    else:
        ledger["source_coordinate"] = {
            **ledger["source_coordinate"],
            "revision": "0" * 40,
        }
    raw = _refresh_ledger_digest(ledger)
    with pytest.raises(EstateError, match=f"^{error}$"):
        validate_applicability_ledger(
            candidate_estate, raw,
            expected_ledger_digest=ledger["ledger_digest"],
        )


def test_applicability_ledger_rejects_digest_mismatch(
    candidate_estate: dict[str, object],
) -> None:
    ledger = applicability_ledger_template(candidate_estate)
    with pytest.raises(EstateError, match="^APPLICABILITY_LEDGER_DIGEST_DIFFERS$"):
        validate_applicability_ledger(
            candidate_estate,
            canonical_bytes(ledger),
            expected_ledger_digest="sha256:" + "f" * 64,
        )


def test_candidate_source_census_includes_provenance_modes_and_git_state(
        candidate_estate: dict[str, object]) -> None:
    census = candidate_estate["pre_source_census"]
    assert census["schema_version"] \
        == estate_module.CANDIDATE_SOURCE_CENSUS_SCHEMA
    assert census["git_index_digest"].startswith("sha256:")
    assert census["git_status_digest"].startswith("sha256:")
    assert census["ignored_scan"]["exclusion_taxonomy_digest"] \
        == estate_module.IGNORED_EXCLUSION_TAXONOMY_DIGEST
    assert census["ignored_scan"]["excluded_bytes_status"] == "NOT_VERIFIED"
    assert census["provenance_counts"][
        "WORKTREE_UNTRACKED_NONIGNORED"
    ] > 0
    for row in census["files"]:
        if row["provenance"] == "GIT_TRACKED":
            assert row["git_mode"] in {"100644", "100755"}
        else:
            assert row["provenance"] == "WORKTREE_UNTRACKED_NONIGNORED"
            assert row["git_mode"] == "UNTRACKED_REGULAR"


def test_public_candidate_source_capture_is_deterministic_under_fixed_state(
        candidate_estate: dict[str, object],
        monkeypatch: pytest.MonkeyPatch) -> None:
    expected = candidate_estate["pre_source_census"]
    tracked = tuple(
        row["path"] for row in expected["files"]
        if row["provenance"] == "GIT_TRACKED"
    )
    untracked = tuple(
        row["path"] for row in expected["files"]
        if row["provenance"] == "WORKTREE_UNTRACKED_NONIGNORED"
    )
    modes = {
        row["path"]: row["git_mode"] for row in expected["files"]
        if row["provenance"] == "GIT_TRACKED"
    }
    monkeypatch.setattr(estate_module, "_git_tracked_paths", lambda root: tracked)
    monkeypatch.setattr(
        estate_module, "_git_untracked_paths", lambda root: untracked,
    )
    monkeypatch.setattr(estate_module, "_git_ignored_paths", lambda root: ())
    monkeypatch.setattr(
        estate_module, "_git_index_state",
        lambda root, selected: (modes, expected["git_index_digest"]),
    )
    monkeypatch.setattr(
        estate_module, "_git_status_digest",
        lambda root: expected["git_status_digest"],
    )
    first = estate_module.capture_candidate_source_census(ROOT)
    second = estate_module.capture_candidate_source_census(ROOT)
    assert first == second


@pytest.mark.parametrize(
    "ignored_path",
    (
        "src/ignored.py", "src/native.dll", "scripts/run", "AGENTS.md",
        "MANIFEST.in", "tox.ini",
    ),
)
def test_public_candidate_source_capture_refuses_ignored_discoverable_source(
        monkeypatch: pytest.MonkeyPatch, ignored_path: str) -> None:
    monkeypatch.setattr(
        estate_module, "_git_ignored_paths", lambda root: (ignored_path,),
    )
    with pytest.raises(
        EstateError, match="^IGNORED_DISCOVERABLE_SOURCE_PRESENT$"
    ):
        estate_module.capture_candidate_source_census(ROOT)


def test_ignored_scan_excludes_root_local_generated_analysis_output() -> None:
    ignored_path = ".vstd-work/reasons-assessment/assessment.json"
    result = estate_module._ignored_scan((ignored_path,))
    assert result["ignored_path_count"] == 1
    assert result["excluded_cache_build_path_count"] == 1
    assert result["excluded_cache_build_paths_digest"] == estate_module.value_digest([
        {
            "path": ignored_path,
            "taxonomy_id": "root-prefix:.vstd-work/",
        },
    ])
    assert result["inert_ignored_path_count"] == 0
    assert result["excluded_bytes_status"] == "NOT_VERIFIED"


@pytest.mark.parametrize("mode,stage", (("120000", "0"), ("100644", "1")))
def test_git_index_refuses_nonordinary_or_nonzero_stage(
        monkeypatch: pytest.MonkeyPatch, mode: str, stage: str) -> None:
    raw = (
        f"{mode} {'a' * 40} {stage}\ttracked.py\0".encode("ascii")
    )
    monkeypatch.setattr(estate_module, "_run_git", lambda *args: raw)
    with pytest.raises(
        EstateError, match="^GIT_INDEX_NOT_ORDINARY_STAGE_ZERO$"
    ):
        estate_module._git_index_state(ROOT, ("tracked.py",))


@pytest.mark.parametrize("relative", ("../outside.py", "/absolute.py", "a\\b.py"))
def test_source_resolver_refuses_escape_or_noncanonical_path(
        relative: str) -> None:
    with pytest.raises(EstateError, match="^CANDIDATE_SOURCE_PATH_INVALID$"):
        estate_module._resolve_source(ROOT, relative)


@pytest.mark.parametrize(
    "drift_field", ("git_index_digest", "git_status_digest")
)
def test_build_refuses_candidate_source_mutation(
        candidate_estate: dict[str, object],
        monkeypatch: pytest.MonkeyPatch, drift_field: str) -> None:
    coordinate = estate_module._git_coordinate(ROOT)
    calls = 0

    def changing(root: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        result = deepcopy(candidate_estate["pre_source_census"])
        if calls == 2:
            result[drift_field] = "sha256:" + "0" * 64
        return result

    monkeypatch.setattr(estate_module, "_git_coordinate", lambda root: coordinate)
    monkeypatch.setattr(
        estate_module, "capture_candidate_source_census", changing,
    )
    with pytest.raises(EstateError, match="^CANDIDATE_SOURCE_MUTATED$"):
        build_candidate_estate(
            ROOT,
            expected_repository=coordinate["repository"],
            expected_revision=coordinate["revision"],
        )


def test_build_refuses_wrong_source_coordinate(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(EstateError, match="^SOURCE_COORDINATE_DIFFERS$"):
        build_candidate_estate(
            ROOT,
            expected_repository="https://example.invalid/substituted.git",
            expected_revision="0" * 40,
        )


def test_installed_registry_drift_is_rejected(
    candidate_estate: dict[str, object], monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = estate_module.core_tier_progression.installed_core_route_inventory()
    changed = deepcopy(inventory)
    changed["registered_route_membership_count"] -= 1
    monkeypatch.setattr(
        estate_module.core_tier_progression,
        "installed_core_route_inventory",
        lambda: changed,
    )
    with pytest.raises(EstateError, match="^INSTALLED_ROUTE_INVENTORY_INVALID$"):
        estate_module._installed_route_rows(
            candidate_estate["pre_source_census"]
        )


def test_parser_route_drift_changes_the_mechanical_route_set() -> None:
    parser = public_cli.build_parser()
    before = estate_module._parser_routes(parser)
    top = next(
        action for action in parser._actions
        if isinstance(action, estate_module.argparse._SubParsersAction)
    )
    removed = sorted(top.choices)[0]
    del top.choices[removed]
    after = estate_module._parser_routes(parser)
    assert after != before
    assert all(not route.startswith(removed) for route, _ in after)


def test_numeric_preparser_drift_is_observable() -> None:
    source = (ROOT / "src/verifier/runtime/public_cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    baseline = estate_module._numeric_preparser_values(tree)
    assert baseline == ("0", "1", "2", "3")
    changed = source.replace('arguments[1] in ("0", "1", "2", "3")',
                             'arguments[1] in ("1",)')
    assert changed != source
    assert estate_module._numeric_preparser_values(ast.parse(changed)) == ("1",)


def test_fixed_resource_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(estate_module, "MAX_GIT_OUTPUT_BYTES", 1)
    with pytest.raises(EstateError, match="^GIT_OUTPUT_CAPACITY_EXHAUSTED$"):
        estate_module._run_git(ROOT, "rev-parse", "HEAD")
    monkeypatch.setattr(estate_module, "MAX_LEDGER_BYTES", 1)
    with pytest.raises(EstateError, match="^APPLICABILITY_LEDGER_CAPACITY_EXHAUSTED$"):
        estate_module._strict_json(b"{}")
