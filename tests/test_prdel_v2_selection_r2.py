"""Refutations for non-circular PRDEL version-two source coordinates."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check_prdel_v2_selection_r2.py"
NATIVE_PROFILE = ROOT / "src/verifier/profiles/prdel-native-v2-selection-2.json"
CLI_PROFILE = ROOT / "src/verifier/profiles/prdel-native-v2-cli-selection-2.json"

SPEC = importlib.util.spec_from_file_location("prdel_v2_selection_checker_r2", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

EXPECTED_MEMBER_PATHS = {
    "scripts/build_component_index.py",
    "scripts/check_pr_description.py",
    "scripts/check_prdel_v2_selection.py",
    "scripts/check_prdel_v2_selection_r2.py",
    "src/verifier/runtime/gate.py",
    "src/verifier/runtime/prdel.py",
    "src/verifier/runtime/prdel_coverage.py",
    "src/verifier/runtime/prdel_evidence.py",
    "src/verifier/runtime/prdel_graph.py",
    "src/verifier/runtime/prdel_rules.py",
    "src/verifier/runtime/prdel_v2_shards.py",
    "src/verifier/schemas/verifier-prdel-2.schema.json",
    "src/verifier/schemas/verifier-prdel-cli-2.schema.json",
    "src/verifier/schemas/verifier-prdel-replay-plan-1.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-document-shard-1.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-release-subject-2.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-shard-manifest-1.schema.json",
    "tests/test_prdel_frontier_redefinition.py",
    "tests/test_prdel_graph_budget.py",
    "tests/test_prdel_graph_source_bound.py",
    "tests/test_prdel_graph_variadic_annotations.py",
    "tests/test_prdel_large_window.py",
    "tests/test_prdel_v2_cli_overlay.py",
    "tests/test_prdel_v2_evidence_replay.py",
    "tests/test_prdel_v2_native.py",
    "tests/test_prdel_v2_selection.py",
    "tests/test_prdel_v2_selection_r2.py",
    "tests/test_prdel_v2_shards.py",
}

DECLARED_METADATA = {
    "ancestor_coordinate_sha256": (
        "2312413c8610fc0e4a7f8fd147e3af4ac8c5d6e557ea77bfaadbd3261e6ecade"
    ),
    "accepted_overlay_patch_sha256": [
        "504b090a9c48629a109150fb0ee0d3c38b75e0223b421fc1f6b6f94e557b0925",
        "5f7fbdd075c30695ee1e81469ed81418a60580293e696ce14aca8a0e9309cf27",
        "b0b17035099841d79d2c1d159557704449220da641cd20440ac9e247c59609d1",
    ],
    "semantic_completeness": "UNKNOWN",
    "release_authorized": False,
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _legacy_subject(native_profile: Path, cli_profile: Path) -> dict[str, Any]:
    native = _load(native_profile)
    return {
        "schema_version": "verifier-prdel-v2-release-subject-1",
        "candidate_status": "DEVELOPMENT_CANDIDATE",
        "implementation_coordinate": native["implementation_coordinate"],
        "profiles": [
            {
                "kind": "NATIVE_V2",
                "path": "src/verifier/profiles/prdel-native-v2-selection-2.json",
                "bytes": native_profile.stat().st_size,
                "sha256": hashlib.sha256(native_profile.read_bytes()).hexdigest(),
            },
            {
                "kind": "NATIVE_V2_CLI",
                "path": "src/verifier/profiles/prdel-native-v2-cli-selection-2.json",
                "bytes": cli_profile.stat().st_size,
                "sha256": hashlib.sha256(cli_profile.read_bytes()).hexdigest(),
            },
        ],
        "declared_metadata": copy.deepcopy(DECLARED_METADATA),
    }


def _subject(
    native_profile: Path,
    cli_profile: Path,
    *,
    base: str,
    head: str,
    description: Path,
) -> dict[str, Any]:
    value = _legacy_subject(native_profile, cli_profile)
    value["schema_version"] = "verifier-prdel-v2-release-subject-2"
    value["source"] = {"base_commit": base, "head_commit": head}
    raw = description.read_bytes()
    value["description"] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return value


def _write_subject(
    root: Path,
    value: dict[str, Any],
) -> tuple[Path, str]:
    path = root / "HOST_RELEASE_SUBJECT.json"
    _write_json(path, value)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _codes(report: dict[str, Any]) -> set[str]:
    return {item["code"] for item in report["findings"]}


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    selected = tmp_path / "candidate"
    for relative in sorted(EXPECTED_MEMBER_PATHS):
        source = ROOT / relative
        destination = selected / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for relative in (
        "src/verifier/profiles/prdel-native-v2-selection-1.json",
        "src/verifier/profiles/prdel-native-v2-selection-2.json",
        "src/verifier/profiles/prdel-native-v2-cli-selection-2.json",
        "src/verifier/standard/PRDEL_NATIVE_V2_COORDINATES.md",
        "src/verifier/standard/PRDEL_NATIVE_V2.md",
        "src/verifier/standard/PRDEL_NATIVE_V2_CLI.md",
    ):
        source = ROOT / relative
        destination = selected / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    native = selected / "src/verifier/profiles/prdel-native-v2-selection-2.json"
    cli = selected / "src/verifier/profiles/prdel-native-v2-cli-selection-2.json"
    _refresh_profiles(selected, native, cli)
    return selected, native, cli


def _refresh_profiles(root: Path, native: Path, cli: Path) -> None:
    inventory = CHECKER._actual_inventory(root)
    coordinate = CHECKER._coordinate(inventory)
    native_value = _load(native)
    native_value["implementation_inventory"] = inventory
    native_value["implementation_coordinate"] = coordinate
    native_value["release_subject_contract"] = copy.deepcopy(CHECKER.RELEASE_SUBJECT_CONTRACT)
    for row in native_value["specifications"]:
        raw = (root / row["path"]).read_bytes()
        row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    _write_json(native, native_value)

    cli_value = _load(cli)
    cli_value["implementation_coordinate"] = coordinate
    cli_value["release_subject_contract"] = copy.deepcopy(CHECKER.RELEASE_SUBJECT_CONTRACT)
    for row in cli_value["specifications"]:
        raw = (root / row["path"]).read_bytes()
        row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    native_raw = native.read_bytes()
    cli_value["native_profile"] = {
        "path": "src/verifier/profiles/prdel-native-v2-selection-2.json",
        "bytes": len(native_raw),
        "sha256": hashlib.sha256(native_raw).hexdigest(),
    }
    _write_json(cli, cli_value)


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout.strip()


def _history_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, str, str, Path, Path, str]:
    root, native, cli = _fixture(tmp_path)
    _git(root, "init", "--quiet", ".")
    _git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    _git(root, "config", "user.name", "Fixture")
    (root / "README.md").write_text("fixture base\n", encoding="utf-8", newline="\n")
    _git(root, "add", "README.md")
    _git(root, "commit", "--quiet", "-m", "fixture base")
    base = _git(root, "rev-parse", "HEAD")

    domains = root / "src/verifier/domains"
    domains.mkdir(parents=True, exist_ok=True)
    (root / "src/verifier/__init__.py").write_text("", encoding="utf-8")
    (domains / "__init__.py").write_text("", encoding="utf-8")
    (domains / "alpha.py").write_text("", encoding="utf-8")
    (domains / "catalog.py").write_text(
        'CHECKS = {"ALPHA": ("alpha",)}\n',
        encoding="utf-8",
        newline="\n",
    )
    core = root / "src/verifier/core"
    core.mkdir(parents=True, exist_ok=True)
    (core / "profile_obligations.py").write_text(
        "# Empty fixture obligation catalogue.\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "pyproject.toml").write_text(
        "[project]\nname = \"fixture\"\nversion = \"0\"\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture selected head")
    head = _git(root, "rev-parse", "HEAD")

    inventory_result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/check_pr_description.py"),
            "--source-inventory",
            "--base",
            base,
            "--commit",
            head,
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )
    inventory = json.loads(inventory_result.stdout)
    for row in inventory["files"]:
        row["summary"] = "Fixture source row selected for production-gate observation."
        row["limits"] = "Fixture evidence does not establish release authority."
    tracked = len(_git(root, "ls-tree", "-r", "--name-only", head).splitlines())
    description = tmp_path / "DESCRIPTION.md"
    description.write_text(
        "This candidate adds one grounded domain adapters with 1 computational checks.\n\n"
        "ALPHA.1–ALPHA.1\n\n"
        f"Current signed head: `{head}`. The tracked inventory is {tracked} files.\n\n"
        "- Repository-check run: 1\n\n"
        "```vstd-source-features\n"
        + json.dumps(inventory, indent=2)
        + "\n```\n",
        encoding="utf-8",
        newline="\n",
    )
    subject, expected_b = _write_subject(
        tmp_path / "host",
        _subject(native, cli, base=base, head=head, description=description),
    )
    return root, native, cli, base, head, description, subject, expected_b


def test_exact_host_selected_two_coordinate_contract_passes(tmp_path: Path) -> None:
    assert set(CHECKER.IMPLEMENTATION_MEMBERS) == EXPECTED_MEMBER_PATHS
    root, native, cli, base, head, description, subject, expected_b = _history_fixture(
        tmp_path
    )
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=description,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "PASS"
    assert report["checked_files"] == 28
    assert report["observed_source"] == {
        "base_commit": base,
        "head_commit": head,
    }
    assert report["observed_description"] == _subject(
        native,
        cli,
        base=base,
        head=head,
        description=description,
    )["description"]
    assert report["release_description_report"] == {
        "findings": [],
        "status": "PASS",
    }
    assert report["findings"] == []


def test_legacy_subject_cannot_qualify_without_source_or_description(
    tmp_path: Path,
) -> None:
    root, native, cli = _fixture(tmp_path)
    subject, expected_b = _write_subject(
        tmp_path / "host",
        _legacy_subject(native, cli),
    )
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "UNKNOWN"
    assert "LEGACY_RELEASE_SUBJECT_SOURCE_BINDING_REQUIRED" in _codes(report)


def test_stale_selected_head_fails_before_description_credit(tmp_path: Path) -> None:
    root, native, cli, base, head, description, _, _ = _history_fixture(tmp_path)
    value = _subject(
        native,
        cli,
        base=base,
        head=head,
        description=description,
    )
    value["source"]["head_commit"] = base
    subject, expected_b = _write_subject(tmp_path / "stale", value)
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=description,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert "RELEASE_SOURCE_HEAD" in _codes(report)
    assert report["release_description_report"] is None


def test_description_substitution_fails_even_when_b_matches(tmp_path: Path) -> None:
    root, native, cli, _, _, description, subject, expected_b = _history_fixture(
        tmp_path
    )
    description.write_text(
        description.read_text(encoding="utf-8") + "substituted after selection\n",
        encoding="utf-8",
        newline="\n",
    )
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=description,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert "RELEASE_DESCRIPTION_BINDING" in _codes(report)
    assert report["release_description_report"] is None


def test_matching_misleading_description_fails_production_gate(tmp_path: Path) -> None:
    root, native, cli, base, head, description, _, _ = _history_fixture(tmp_path)
    body = description.read_text(encoding="utf-8").replace(
        f"Current signed head: `{head}`. ",
        "",
    )
    description.write_text(body, encoding="utf-8", newline="\n")
    subject, expected_b = _write_subject(
        tmp_path / "misleading",
        _subject(
            native,
            cli,
            base=base,
            head=head,
            description=description,
        ),
    )
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=description,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert "RELEASE_DESCRIPTION_GATE" in _codes(report)
    assert report["release_description_report"]["status"] == "FAIL"
    assert any(
        "Current signed head" in finding
        for finding in report["release_description_report"]["findings"]
    )


def test_absent_exact_description_remains_unknown(tmp_path: Path) -> None:
    root, native, cli, _, _, _, subject, expected_b = _history_fixture(tmp_path)
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=None,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "UNKNOWN"
    assert "HOST_RELEASE_DESCRIPTION_REQUIRED" in _codes(report)


def test_coordinate_binds_runtime_coverage_and_named_adversarial_checks() -> None:
    assert {
        "src/verifier/runtime/prdel_coverage.py",
        "src/verifier/runtime/prdel_evidence.py",
        "src/verifier/schemas/verifier-prdel-replay-plan-1.schema.json",
        "tests/test_prdel_graph_variadic_annotations.py",
        "tests/test_prdel_large_window.py",
        "tests/test_prdel_v2_evidence_replay.py",
    } <= set(CHECKER.IMPLEMENTATION_MEMBERS)


def test_cli_profile_selects_only_bounded_replay_and_closed_frontier_catalogue() -> None:
    assert _load(CLI_PROFILE)["capabilities"] == {
        "render_explicit_v2_document": "SELECTED",
        "validate_complete_private_v2_shards": "SELECTED",
        "independent_bounded_replay": "SELECTED",
        "closed_catalogue_frontier_resolvers": "SELECTED",
        "rule_compilation": "UNSUPPORTED_UNKNOWN",
        "authored_definitions": "UNSUPPORTED_UNKNOWN",
        "preventative_comparison": "UNSUPPORTED_UNKNOWN",
        "impact_dag": "UNSUPPORTED_UNKNOWN",
        "frontier_discharge": "UNSUPPORTED_UNKNOWN",
        "core_registration": "OUT_OF_SCOPE",
    }


def test_code_mutation_invalidates_implementation_coordinate(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path)
    selected = root / "src/verifier/runtime/prdel_graph.py"
    selected.write_bytes(selected.read_bytes() + b"\n")
    subject, expected_b = _write_subject(tmp_path / "host", _legacy_subject(native, cli))
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert {"IMPLEMENTATION_BYTES", "IMPLEMENTATION_SHA256", "IMPLEMENTATION_COORDINATE"} <= _codes(report)


def test_profile_mutation_changes_b_but_not_a_and_stale_binding_fails(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path)
    coordinate_before = CHECKER.compute_implementation_coordinate(root)
    old_subject, old_b = _write_subject(tmp_path / "old", _legacy_subject(native, cli))
    value = _load(native)
    value["claim_boundary"] += " Additive host-review marker."
    _write_json(native, value)
    coordinate_after = CHECKER.compute_implementation_coordinate(root)
    new_subject, new_b = _write_subject(tmp_path / "new", _legacy_subject(native, cli))
    assert coordinate_after == coordinate_before
    assert new_b != old_b
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=old_subject,
        expected_release_subject_sha256=old_b,
    )
    assert report["status"] == "FAIL"
    assert {"CLI_NATIVE_PROFILE", "RELEASE_PROFILE_BINDING"} <= _codes(report)
    assert new_subject.is_file()


@pytest.mark.parametrize("mutation", ["missing", "changed"])
def test_retained_r1_profile_live_path_is_observed(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, native, cli = _fixture(tmp_path)
    retained = root / CHECKER.R1_NATIVE_PROFILE_PATH
    if mutation == "missing":
        retained.unlink()
    else:
        retained.write_bytes(retained.read_bytes() + b"\n")

    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=None,
        expected_release_subject_sha256=None,
    )

    assert report["status"] == "FAIL"
    assert "LEGACY_PROFILE_SOURCE" in _codes(report)


def test_retained_r1_profile_is_part_of_exact_head_binding(tmp_path: Path) -> None:
    root, native, cli, _, _, description, subject, expected_b = _history_fixture(
        tmp_path
    )
    retained = root / CHECKER.R1_NATIVE_PROFILE_PATH
    retained.write_bytes(retained.read_bytes() + b"\n")

    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        release_description=description,
        expected_release_subject_sha256=expected_b,
    )

    assert report["status"] == "FAIL"
    assert {
        "LEGACY_PROFILE_SOURCE",
        "RELEASE_SOURCE_MEMBER_BINDING",
    } <= _codes(report)


def test_foreign_implementation_coordinate_fails(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path)
    value = _load(cli)
    value["implementation_coordinate"]["sha256"] = "0" * 64
    _write_json(cli, value)
    subject, expected_b = _write_subject(tmp_path / "host", _legacy_subject(native, cli))
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert "CLI_IMPLEMENTATION_COORDINATE" in _codes(report)


def test_foreign_host_selected_b_fails(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path / "fixture")
    subject, _ = _write_subject(tmp_path, _legacy_subject(native, cli))
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256="0" * 64,
    )
    assert report["status"] == "FAIL"
    assert "HOST_RELEASE_SUBJECT" in _codes(report)


def test_substituted_profile_binding_fails_even_when_b_matches(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path / "fixture")
    value = _legacy_subject(native, cli)
    value["profiles"][0]["sha256"] = "0" * 64
    subject, expected_b = _write_subject(tmp_path, value)
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=expected_b,
    )
    assert report["status"] == "FAIL"
    assert "RELEASE_PROFILE_BINDING" in _codes(report)


def test_absent_host_selection_remains_unknown(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path / "fixture")
    subject, _ = _write_subject(tmp_path, _legacy_subject(native, cli))
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=None,
    )
    assert report["status"] == "UNKNOWN"
    assert "HOST_SELECTION_REQUIRED" in _codes(report)


def test_candidate_cannot_embed_and_reselect_its_own_b(tmp_path: Path) -> None:
    root, native, cli = _fixture(tmp_path / "fixture")
    value = _legacy_subject(native, cli)
    value["expected_release_subject_sha256"] = "0" * 64
    subject, _ = _write_subject(tmp_path, value)
    report = CHECKER.check_selection(
        root,
        native,
        cli,
        host_release_subject=subject,
        expected_release_subject_sha256=None,
    )
    assert report["status"] == "FAIL"
    assert "RELEASE_SUBJECT_FIELDS" in _codes(report)
