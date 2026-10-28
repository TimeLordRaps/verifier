"""Falsification controls for the non-executing package launch denominator.

Terminology: abstract syntax tree (AST).
"""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import package_harness_applicability as harness


ROOT = Path(__file__).parents[1]
WORKER_CONTAINER = '''WORKER = """import subprocess\nsubprocess.run([\"compiler\"])\nsubprocess.run([\"subject\"])\n"""\n'''


def repository(tmp_path: Path, source: str, worker: str = WORKER_CONTAINER) -> Path:
    root = tmp_path / "selected"
    package = root / "src" / "verifier"
    extension = root / "extensions" / "languages" / "src" / "vstd_languages"
    package.mkdir(parents=True)
    extension.mkdir(parents=True)
    (package / "sample.py").write_text(source, encoding="utf-8")
    (extension / "__init__.py").write_text(worker, encoding="utf-8")
    return root


def declared(root: Path) -> tuple[dict, ...]:
    discovery = harness.discover_repository(root)
    assert discovery["status"] == "PASS", discovery["issues"]
    return harness.declarations_from_discovery(discovery, {
        row["launch_id"]: {
            "necessity_reason": "This selected fixture launch is required for its explicit test role.",
            "observation_disposition": "SOURCE_ENUMERATION_ONLY",
            "unobserved_gaps": ["reachability", "runtime-outcome"],
        }
        for row in discovery["launches"]
    })


def finding_codes(report: dict) -> set[str]:
    return {finding["code"] for finding in report["findings"]}


# The frozen 32-row denominator is superseded by the reviewed 40-row advance (the 39-row
# advance plus the MODEL corrigibility isolated-worker launch).  The two removed launches
# are proven absent for their refactor reasons below.  Migration acceptance of the advance
# belongs to package_manifest_migration and is asserted here only as a refusal until that
# owner installs its exact transition.
REMOVED_LAUNCH_IDS = frozenset({
    "src/verifier/core/run.py|scope=<module>.<locals>.capture_run|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/package_execution.py|scope=<module>.<locals>.execute_bound|callee=subprocess.run|ordinal=1",
})
# The execute_bound call AST, relocated unchanged into _run_package_worker.
RELOCATED_PACKAGE_CALL = "sha256:efddd4e037130fe0e623fe3075b338ce202d6fab2f045b41849a94790a285097"
# The prior ordinal-2 subject-run call AST, now carried by WORKER ordinal 6.
PRIOR_SUBJECT_RUN_CALL = "sha256:8ab8c03a43ca545669187e5c9569971be2dc3b916bcd16922c10a3ca5947f025"
WORKER_ID = "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal="
OWNED_PROCESS_ID = "src/verifier/core/owned_process.py|scope=<module>.<locals>.PosixOwnedTree.<locals>.launch|callee=subprocess.Popen|ordinal=1"
MODEL_CORRIGIBILITY_ID = (
    "src/verifier/domains/contracts/model_corrigibility.py"
    "|scope=<module>.<locals>._invoke_worker|callee=subprocess.run|ordinal=1"
)
ADDED_LAUNCH_IDS = frozenset({
    MODEL_CORRIGIBILITY_ID,
    WORKER_ID + "3",
    WORKER_ID + "4",
    WORKER_ID + "5",
    WORKER_ID + "6",
    OWNED_PROCESS_ID,
    "src/verifier/runtime/added_kind_behavioral_routes.py|scope=<module>.<locals>.retained_policy_observations|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/package_execution.py|scope=<module>.<locals>._run_package_worker|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/policy_enforcement_execution.py|scope=<module>.<locals>._repository_state|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/policy_enforcement_routes.py|scope=<module>.<locals>.evaluate_routes|callee=subprocess.run|ordinal=1",
})
REASONING_LAUNCH_IDS = frozenset({
    "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py|scope=<module>.<locals>._git_python_files|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>.<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1",
    "src/verifier/runtime/tier_zero_reasoning/witness_runner.py|scope=<module>.<locals>.run_one|callee=subprocess.run|ordinal=1",
})


def _catalog_by_id() -> dict[str, dict]:
    return {row["launch_id"]: row for row in harness.PACKAGE_LAUNCH_DECLARATIONS}


def _calls_in(function: ast.AST) -> set[str]:
    return {ast.unparse(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}


def _top_level_function(relative: str, name: str) -> ast.FunctionDef:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    return next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name)


def _mutant_tree(tmp_path: Path, relative: str, old: str, new: str) -> tuple[Path, tuple[dict, ...]]:
    """Copy one mutated source plus the embedded worker; declare only those paths."""

    root = tmp_path / "mutant"
    for path in (relative, harness.EMBEDDED_WORKER_PATH):
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / path).read_bytes())
    target = root / relative
    raw = target.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8").replace("\r\n", "\n")
    assert text.count(old) == 1, relative
    # Preserve the source's own newline bytes: an identity mutation must reproduce it exactly.
    target.write_bytes(text.replace(old, new, 1).replace("\n", newline).encode("utf-8"))
    scoped = tuple(row for row in harness.PACKAGE_LAUNCH_DECLARATIONS
                   if row["path"] in {relative, harness.EMBEDDED_WORKER_PATH})
    return root, scoped


def test_current_package_has_exact_reviewed_45_direct_launch_denominator() -> None:
    report = harness.assess_repository(ROOT)
    assert report["status"] == "PASS", report["findings"]
    assert report["declared_launch_count"] == report["discovered_launch_count"] == 45
    assert report["ordinary_launch_count"] == 39
    assert report["embedded_launch_count"] == 6
    assert report["profile"] == "verifier-self-direct-python-launches-1"
    assert report["applicability"] == "VERIFIER_SELF_ONLY"
    assert len(harness.PACKAGE_LAUNCH_DECLARATIONS) == 45
    assert all(row["necessity_reason"].strip() for row in harness.PACKAGE_LAUNCH_DECLARATIONS)
    assert all(row["unobserved_gaps"] for row in harness.PACKAGE_LAUNCH_DECLARATIONS)
    # The removed capture_run row was the only PARENT_INTERFACE_OBSERVED row; it is not
    # silently transferred to the owned-process launch, which stays source-enumerated.
    assert {row["observation_disposition"] for row in harness.PACKAGE_LAUNCH_DECLARATIONS} == {
        "SOURCE_ENUMERATION_ONLY"}
    assert report["unobserved_gaps"] == sorted({gap
        for row in harness.PACKAGE_LAUNCH_DECLARATIONS
        for gap in row["unobserved_gaps"]})
    assert "No claim about reachability" in report["claim_boundary"]
    assert "HARNESS conformance" in report["claim_boundary"]
    assert "not a generic third-party package requirement" in report["claim_boundary"]


def test_reviewed_denominator_is_exactly_the_live_45_identity_set() -> None:
    discovery = harness.discover_repository(ROOT)
    assert discovery["status"] == "PASS", discovery["issues"]
    live = {row["launch_id"] for row in discovery["launches"]}
    catalog = _catalog_by_id()
    assert len(harness.PACKAGE_LAUNCH_DECLARATIONS) == len(catalog) == len(live) == 45
    assert set(catalog) == live
    assert ADDED_LAUNCH_IDS <= live
    assert len(ADDED_LAUNCH_IDS) == 10
    assert REASONING_LAUNCH_IDS <= live
    assert len(REASONING_LAUNCH_IDS) == 5
    assert not (REMOVED_LAUNCH_IDS & live)
    # 32 prior - 2 removed = 30 retained; 10 earlier and 5 reasoning additions.
    assert len(live - ADDED_LAUNCH_IDS - REASONING_LAUNCH_IDS) == 30


def test_removed_capture_run_launch_is_absent_because_it_routes_through_owned_process() -> None:
    capture = _top_level_function("src/verifier/core/run.py", "capture_run")
    calls = _calls_in(capture)
    assert "subprocess.run" not in calls and "subprocess.Popen" not in calls
    assert {"_run_owned_process", "begin_parent_process_observation"} <= calls
    owned_adapter = _top_level_function("src/verifier/core/run.py", "_run_owned_process")
    assert "_owned_process.run_owned_process" in _calls_in(owned_adapter)
    assert OWNED_PROCESS_ID in ADDED_LAUNCH_IDS


def test_removed_execute_bound_launch_is_relocated_with_the_same_call_ast() -> None:
    execute = _top_level_function("src/verifier/runtime/package_execution.py", "execute_bound")
    calls = _calls_in(execute)
    assert "subprocess.run" not in calls and "_run_package_worker" in calls
    discovery = harness.discover_repository(ROOT)
    relocated = [row for row in discovery["launches"]
                 if row["scope"] == "<module>.<locals>._run_package_worker"]
    assert [row["call_sha256"] for row in relocated] == [RELOCATED_PACKAGE_CALL]


def test_worker_ordinal_two_keeps_its_identity_with_a_new_meaning() -> None:
    catalog = _catalog_by_id()
    go_build = catalog[WORKER_ID + "2"]
    subject_run = catalog[WORKER_ID + "6"]
    assert go_build["call_sha256"] != PRIOR_SUBJECT_RUN_CALL
    assert "Go language branch" in go_build["necessity_reason"]
    assert subject_run["call_sha256"] == PRIOR_SUBJECT_RUN_CALL
    assert "execute the newly compiled subject" in subject_run["necessity_reason"]


def test_each_added_launch_has_a_feature_near_reason_closed_disposition_and_non_claim_gaps() -> None:
    catalog = _catalog_by_id()
    assert ADDED_LAUNCH_IDS <= set(catalog)
    for launch_id in sorted(ADDED_LAUNCH_IDS):
        row = catalog[launch_id]
        assert row["necessity_reason"].strip(), launch_id
        assert row["observation_disposition"] in harness.DISPOSITIONS, launch_id
        assert row["observation_disposition"] == "SOURCE_ENUMERATION_ONLY", launch_id
        assert {"reachability", "descendants", "sandboxing", "runtime-outcome"} <= set(
            row["unobserved_gaps"]), launch_id
        assert not {"sandboxed", "conformant", "cleanup-confirmed"} & set(
            row["necessity_reason"].lower().split()), launch_id


@pytest.mark.parametrize(("finding", "expected_codes"), [
    ("omit", {"UNDECLARED_DIRECT_LAUNCH"}),
    ("duplicate", {"DECLARATION_ID_INVALID"}),
    ("forged-extra", {"DECLARED_DIRECT_LAUNCH_MISSING"}),
])
def test_omitted_duplicate_or_forged_additions_fail_closed(
        finding: str, expected_codes: set[str]) -> None:
    catalog = list(harness.PACKAGE_LAUNCH_DECLARATIONS)
    added = _catalog_by_id()[OWNED_PROCESS_ID]
    if finding == "omit":
        selected = [row for row in catalog if row is not added]
    elif finding == "duplicate":
        selected = catalog + [dict(added)]
    else:
        forged: dict = {**added, "ordinal": added["ordinal"] + 99, "line": 1}
        forged["launch_id"] = harness._identity(
            forged["path"], forged["embedded_name"], forged["scope"],
            forged["callee"], forged["ordinal"])
        selected = catalog + [forged]
    report = harness.assess_repository(ROOT, selected)
    assert report["status"] == "REFUTED"
    assert expected_codes <= finding_codes(report)


def test_forged_reason_or_missing_gaps_on_an_added_launch_fail_closed() -> None:
    added = dict(_catalog_by_id()[WORKER_ID + "3"])
    assert not harness._declaration_issues([added])
    blank = dict(added, necessity_reason="   ")
    assert {issue["code"] for issue in harness._declaration_issues([blank])} == {
        "DECLARATION_REASON_REQUIRED"}
    ungapped = dict(added, unobserved_gaps=[])
    assert {issue["code"] for issue in harness._declaration_issues([ungapped])} == {
        "DECLARATION_GAPS_REQUIRED"}


@pytest.mark.parametrize(("relative", "old", "new", "expected"), [
    (
        "src/verifier/core/run.py",
        "            owned = _run_owned_process(command_tuple, cwd, timeout_seconds)\n",
        "            owned = _run_owned_process(command_tuple, cwd, timeout_seconds)\n"
        "            subprocess.run([], check=False)\n",
        {"UNDECLARED_DIRECT_LAUNCH"},
    ),
    (
        "src/verifier/runtime/package_execution.py",
        "        completed = subprocess.run(command, **child_parameters)\n",
        "        completed = subprocess.run(command, check=True, **child_parameters)\n",
        {"DIRECT_LAUNCH_SOURCE_CHANGED", "DIRECT_LAUNCH_CALL_CHANGED"},
    ),
    (
        "src/verifier/runtime/package_execution.py",
        "    if subprocess.run is not _STANDARD_SUBPROCESS_RUN:\n",
        "    subprocess.run(['extra'], check=False)\n"
        "    if subprocess.run is not _STANDARD_SUBPROCESS_RUN:\n",
        {"UNDECLARED_DIRECT_LAUNCH", "DIRECT_LAUNCH_CALL_CHANGED"},
    ),
])
def test_ordinary_source_and_call_drift_on_the_reviewed_tree_stays_refuted(
        tmp_path: Path, relative: str, old: str, new: str, expected: set[str]) -> None:
    root, scoped = _mutant_tree(tmp_path, relative, old, new)
    report = harness.assess_repository(root, scoped)
    assert report["status"] == "REFUTED"
    assert expected <= finding_codes(report)


@pytest.mark.parametrize("extra", [
    "subprocess.run(['one'])\n",
    "subprocess.Popen(['two'])\n",
])
def test_refresh_refuses_a_semantically_different_extra_launch(
        tmp_path: Path, extra: str) -> None:
    root = repository(tmp_path, "import subprocess\ndef launch():\n    subprocess.run(['one'])\n")
    baseline = declared(root)
    sample = root / "src" / "verifier" / "sample.py"
    sample.write_text(sample.read_text(encoding="utf-8") + "def extra():\n    " + extra,
                      encoding="utf-8")
    with pytest.raises(ValueError, match="PACKAGE_HARNESS_LAUNCH_DENOMINATOR_CHANGED"):
        harness.refresh_source_bindings(root, baseline)


def test_policy_repository_state_same_call_semantics_mutant_is_refuted(tmp_path: Path) -> None:
    """Keep the reviewed _repository_state call text but make its failure branch fail open."""

    relative = "src/verifier/runtime/policy_enforcement_execution.py"
    old = '    if completed.returncode != 0:\n        return "UNKNOWN"\n'
    new = '    if completed.returncode != 0:\n        return "CLEAN_NOT_BLESSED"\n'

    control_root, control_scoped = _mutant_tree(tmp_path / "control", relative, old, old)
    control = harness.assess_repository(control_root, control_scoped)
    assert control["status"] == "PASS", control["findings"]

    root, scoped = _mutant_tree(tmp_path / "mutant", relative, old, new)
    report = harness.assess_repository(root, scoped)
    assert report["status"] == "REFUTED"
    codes = finding_codes(report)
    assert "DIRECT_LAUNCH_SOURCE_CHANGED" in codes
    assert "DIRECT_LAUNCH_CALL_CHANGED" not in codes


def test_reviewed_45_denominator_round_trips_through_the_manifest_owner() -> None:
    catalog = tuple(dict(row) for row in harness.PACKAGE_LAUNCH_DECLARATIONS)
    owner = {
        "surfaces": [harness.SELECTION_SURFACE],
        "payload": {"direct_launch_denominator": harness.denominator_document(catalog)},
    }
    assert harness.declarations_from_manifest_owner(owner) == catalog
    assert harness.refresh_source_bindings(ROOT, catalog) == catalog
    declaration = {"objects": [{
        "object_id": "vstd-harness",
        "kind": "HARNESS",
        "specializations": [],
        "surfaces": [harness.SELECTION_SURFACE],
        "payload": owner["payload"],
    }]}
    report = harness.assess_selected_repository(ROOT, declaration)
    assert report["status"] == "PASS", report["findings"]
    assert report["owner_object_id"] == "vstd-harness"
    assert report["declared_launch_count"] == 45


@pytest.mark.parametrize(("select_profile", "refresh_reviewed"), [
    (False, True),
    (True, False),
    (False, False),
])
def test_advance_requires_the_explicit_select_and_refresh_pair(
        select_profile: bool, refresh_reviewed: bool) -> None:
    from verifier.runtime import namespace_manifest
    from verifier.runtime import package_manifest_migration as migration

    _, document = namespace_manifest.read_manifest(ROOT / "objects.vstd")
    owner = next(row for row in document["namespace"]["objects"]
                 if row["object_id"] == "vstd-harness")
    with pytest.raises(ValueError, match="PACKAGE_HARNESS_ADVANCE_REQUIRES_EXPLICIT_REVIEW"):
        migration._refresh_harness_launch_denominator(
            ROOT,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=select_profile,
            refresh_reviewed=refresh_reviewed,
            advance_reviewed=True,
        )


def test_migration_installed_latest_harness_advance_is_exact() -> None:
    """The reviewed PRDEL large-artifact source-AST refresh is installed.

    Partial, forged, and future candidates remain refused in the migration tests.
    """

    from verifier.runtime import namespace_manifest
    from verifier.runtime import package_manifest_migration as migration

    _, document = namespace_manifest.read_manifest(ROOT / "objects.vstd")
    owner = next(row for row in document["namespace"]["objects"]
                 if row["object_id"] == "vstd-harness")
    destination = {"surfaces": [harness.SELECTION_SURFACE], "payload": {}}
    migration._refresh_harness_launch_denominator(
        ROOT,
        destination,
        owner,
        select_profile=True,
        refresh_reviewed=True,
        advance_reviewed=True,
    )
    launches = destination["payload"]["direct_launch_denominator"]["launches"]
    assert len(launches) == 45
    assert migration.value_digest(launches) == (
        migration._PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION[
            "refreshed"
        ]
    )


def test_package_execution_source_body_drift_refutes_unchanged_launch_call(
        tmp_path: Path) -> None:
    """Keep the reviewed package worker launch bound to its complete source body."""

    selected = tmp_path / "selected"
    source_relative = "src/verifier/runtime/package_execution.py"
    for relative in (source_relative, harness.EMBEDDED_WORKER_PATH):
        destination = selected / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    reviewed = tuple(
        row for row in harness.PACKAGE_LAUNCH_DECLARATIONS
        if row["path"] in {source_relative, harness.EMBEDDED_WORKER_PATH}
    )
    package_launch = next(row for row in reviewed if row["path"] == source_relative)
    assert package_launch["necessity_reason"] == (
        "A trusted in-process test seam must route the package worker invocation through the "
        "injected subprocess.run object; production launches use the owned-process primitive instead."
    )
    assert package_launch["unobserved_gaps"] == [
        *harness.DEFAULT_UNOBSERVED, "test-seam-only-when-run-replaced"]
    baseline = harness.assess_repository(selected, reviewed)
    assert baseline["status"] == "PASS", baseline["findings"]

    source = selected / source_relative
    current = source.read_text(encoding="utf-8")
    changed = current.replace(
        "Run one fixed worker after matching every executable source dependency.",
        "Run one fixed worker after matching each executable source dependency.",
        1,
    )
    assert changed != current
    source.write_text(changed, encoding="utf-8")

    drift = harness.assess_repository(selected, reviewed)
    assert drift["status"] == "REFUTED"
    assert finding_codes(drift) == {"DIRECT_LAUNCH_SOURCE_CHANGED"}
    observed = next(
        row for row in drift["discovery"]["launches"]
        if row["launch_id"] == package_launch["launch_id"]
    )
    assert observed["call_sha256"] == package_launch["call_sha256"]
    assert observed["source_sha256"] != package_launch["source_sha256"]


def test_supported_aliases_and_process_api_vocabulary_are_discovered(tmp_path: Path) -> None:
    subprocess_members = (
        "run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput",
    )
    asyncio_members = ("create_subprocess_exec", "create_subprocess_shell")
    os_members = (
        "system", "popen", "fork", "forkpty", "startfile", "execl", "execle", "execlp",
        "execlpe", "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle",
        "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "posix_spawn", "posix_spawnp",
    )
    source = "import subprocess as sp\nimport asyncio as aio\nimport os as operating_system\n"
    source += "\n".join(f"sp.{name}()" for name in subprocess_members) + "\n"
    source += "\n".join(f"aio.{name}()" for name in asyncio_members) + "\n"
    source += "\n".join(f"operating_system.{name}()" for name in os_members) + "\n"
    source += (
        "from subprocess import run as direct\n"
        "saved, marker = direct, None\n"
        "def nested():\n"
        "    saved()\n"
    )
    report = harness.discover_repository(repository(tmp_path, source))
    assert report["status"] == "PASS", report["issues"]
    expected = ({f"subprocess.{name}" for name in subprocess_members}
                | {f"asyncio.{name}" for name in asyncio_members}
                | {f"os.{name}" for name in os_members})
    ordinary = [row for row in report["launches"] if row["embedded_name"] is None]
    assert {row["callee"] for row in ordinary} == expected
    assert len(ordinary) == len(expected) + 1, "The aliased second subprocess.run remains a distinct site."
    assert any(row["scope"].endswith("nested") and row["callee"] == "subprocess.run"
               for row in ordinary)


def test_identity_uses_path_scope_callee_ordinal_while_line_remains_diagnostic(
        tmp_path: Path) -> None:
    root = repository(tmp_path, "import subprocess as sp\ndef launch():\n    sp.run(['x'])\n")
    before = harness.discover_repository(root)["launches"]
    ordinary_before = next(row for row in before if row["embedded_name"] is None)
    sample = root / "src" / "verifier" / "sample.py"
    sample.write_text("\n\n" + sample.read_text(encoding="utf-8"), encoding="utf-8")
    after = harness.discover_repository(root)["launches"]
    ordinary_after = next(row for row in after if row["embedded_name"] is None)
    assert ordinary_after["launch_id"] == ordinary_before["launch_id"]
    assert ordinary_after["line"] == ordinary_before["line"] + 2
    assert "scope=<module>.<locals>.launch" in ordinary_after["launch_id"]
    assert "callee=subprocess.run|ordinal=1" in ordinary_after["launch_id"]
    assert f"line={ordinary_before['line']}" not in ordinary_before["launch_id"]


def test_new_direct_launch_refutes_frozen_denominator(tmp_path: Path) -> None:
    root = repository(tmp_path, "import subprocess\ndef launch():\n    subprocess.run(['one'])\n")
    baseline = declared(root)
    sample = root / "src" / "verifier" / "sample.py"
    sample.write_text(sample.read_text(encoding="utf-8") + "subprocess.check_call(['two'])\n",
                      encoding="utf-8")
    report = harness.assess_repository(root, baseline)
    assert report["status"] == "REFUTED"
    assert "UNDECLARED_DIRECT_LAUNCH" in finding_codes(report)


def test_missing_direct_launch_refutes_frozen_denominator(tmp_path: Path) -> None:
    root = repository(tmp_path,
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n    subprocess.call(['two'])\n")
    baseline = declared(root)
    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n", encoding="utf-8")
    report = harness.assess_repository(root, baseline)
    assert report["status"] == "REFUTED"
    assert "DECLARED_DIRECT_LAUNCH_MISSING" in finding_codes(report)


def test_mutated_call_and_exact_source_bytes_refute_frozen_denominator(tmp_path: Path) -> None:
    root = repository(tmp_path, "import subprocess\ndef launch():\n    subprocess.run(['one'])\n")
    baseline = declared(root)
    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ndef launch():\n    subprocess.run(['changed'])\n", encoding="utf-8")
    report = harness.assess_repository(root, baseline)
    assert report["status"] == "REFUTED"
    assert {"DIRECT_LAUNCH_SOURCE_CHANGED", "DIRECT_LAUNCH_CALL_CHANGED"} <= finding_codes(report)


def test_refresh_source_bindings_accepts_only_source_and_line_rebinding(
        tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n",
    )
    baseline = declared(root)
    sample = root / "src" / "verifier" / "sample.py"
    sample.write_text(
        "# source-only movement\n" + sample.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    refreshed = harness.refresh_source_bindings(root, baseline)

    assert {row["launch_id"] for row in refreshed} == {
        row["launch_id"] for row in baseline
    }
    before = {row["launch_id"]: row for row in baseline}
    after = {row["launch_id"]: row for row in refreshed}
    ordinary_id = next(
        launch_id for launch_id, row in before.items()
        if row["embedded_name"] is None
    )
    assert after[ordinary_id]["source_sha256"] != before[ordinary_id]["source_sha256"]
    assert after[ordinary_id]["line"] == before[ordinary_id]["line"] + 1
    assert after[ordinary_id]["call_sha256"] == before[ordinary_id]["call_sha256"]
    assert after[ordinary_id]["necessity_reason"] == before[ordinary_id]["necessity_reason"]


def test_refresh_source_bindings_refuses_changed_call(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n",
    )
    baseline = declared(root)
    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ndef launch():\n    subprocess.run(['changed'])\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_LAUNCH_CALL_CHANGED"):
        harness.refresh_source_bindings(root, baseline)


def test_migration_advances_changed_call_only_for_explicit_review_pair(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import package_manifest_migration as migration

    root = repository(
        tmp_path,
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n",
    )
    baseline = declared(root)
    owner = {
        "surfaces": [harness.SELECTION_SURFACE],
        "payload": {"direct_launch_denominator": harness.denominator_document(baseline)},
    }
    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ndef launch():\n    subprocess.run(['reviewed'])\n",
        encoding="utf-8",
    )
    reviewed = harness.declarations_from_discovery(
        harness.discover_repository(root),
        {
            row["launch_id"]: {
                "necessity_reason": row["necessity_reason"],
                "observation_disposition": row["observation_disposition"],
                "unobserved_gaps": row["unobserved_gaps"],
            }
            for row in baseline
        },
    )
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", reviewed)

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_LAUNCH_CALL_CHANGED"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=True,
            refresh_reviewed=False,
            advance_reviewed=False,
        )

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_LAUNCH_CALL_CHANGED"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=True,
            refresh_reviewed=True,
            advance_reviewed=False,
        )

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_LAUNCH_CALL_CHANGED"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=False,
            refresh_reviewed=True,
            advance_reviewed=False,
        )

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_ADVANCE_REQUIRES_EXPLICIT_REVIEW"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=False,
            refresh_reviewed=True,
            advance_reviewed=True,
        )

    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", ())
    with pytest.raises(ValueError, match="PACKAGE_HARNESS_REVIEWED_DENOMINATOR_CHANGED"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=True,
            refresh_reviewed=True,
            advance_reviewed=True,
        )
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", reviewed)

    with pytest.raises(ValueError, match="PACKAGE_HARNESS_REVIEWED_DENOMINATOR_CHANGED"):
        migration._refresh_harness_launch_denominator(
            root,
            {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
            owner,
            select_profile=True,
            refresh_reviewed=True,
            advance_reviewed=True,
        )

    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n",
        encoding="utf-8",
    )
    current_catalog = deepcopy(baseline)
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", current_catalog)

    embedded_index = next(
        index for index, record in enumerate(current_catalog)
        if "container_sha256" in record
    )
    for index, field in (
        (0, "source_sha256"),
        (embedded_index, "container_sha256"),
    ):
        stale_catalog = deepcopy(current_catalog)
        stale_catalog[index][field] = "sha256:" + "0" * 64
        monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", stale_catalog)
        with pytest.raises(
            ValueError, match="PACKAGE_HARNESS_REVIEWED_CATALOG_NOT_CURRENT"
        ):
            migration._refresh_harness_launch_denominator(
                root,
                {"surfaces": [harness.SELECTION_SURFACE], "payload": {}},
                owner,
                select_profile=True,
                refresh_reviewed=True,
                advance_reviewed=True,
            )
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", current_catalog)

    destination = {"surfaces": [harness.SELECTION_SURFACE], "payload": {}}
    migration._refresh_harness_launch_denominator(
        root,
        destination,
        owner,
        select_profile=True,
        refresh_reviewed=True,
        advance_reviewed=True,
    )
    assert destination["payload"]["direct_launch_denominator"] == (
        harness.denominator_document(current_catalog)
    )


def test_refresh_source_bindings_refuses_changed_file_ast_with_same_call(
        tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        "import subprocess\ncommand = ['safe']\nsubprocess.run(command)\n",
    )
    baseline = declared(root)
    (root / "src" / "verifier" / "sample.py").write_text(
        "import subprocess\ncommand = ['changed']\nsubprocess.run(command)\n",
        encoding="utf-8",
    )

    discovery = harness.discover_repository(root)
    prior = next(row for row in baseline if row["embedded_name"] is None)
    current = next(
        row for row in discovery["launches"] if row["embedded_name"] is None
    )
    assert current["call_sha256"] == prior["call_sha256"]
    with pytest.raises(ValueError, match="PACKAGE_HARNESS_SOURCE_AST_CHANGED"):
        harness.refresh_source_bindings(root, baseline)


@pytest.mark.parametrize("worker, expected", [
    (
        '''WORKER = """import subprocess\nsubprocess.run([\"changed\"])\nsubprocess.run([\"subject\"])\n"""\n''',
        {"DIRECT_LAUNCH_SOURCE_CHANGED", "DIRECT_LAUNCH_CALL_CHANGED",
         "EMBEDDED_WORKER_CONTAINER_CHANGED"},
    ),
    (
        '''WORKER = """import subprocess\nsubprocess.run([\"compiler\"])\n"""\n''',
        {"DECLARED_DIRECT_LAUNCH_MISSING", "EMBEDDED_WORKER_CONTAINER_CHANGED"},
    ),
])
def test_changed_or_missing_embedded_worker_launch_refutes_denominator(
        tmp_path: Path, worker: str, expected: set[str]) -> None:
    root = repository(tmp_path, "", WORKER_CONTAINER)
    baseline = declared(root)
    (root / harness.EMBEDDED_WORKER_PATH).write_text(worker, encoding="utf-8")
    report = harness.assess_repository(root, baseline)
    assert report["status"] == "REFUTED"
    assert expected <= finding_codes(report)


def test_dynamic_process_selection_is_explicit_ambiguity(tmp_path: Path) -> None:
    root = repository(tmp_path,
        "import subprocess as sp\nname = 'run'\nlauncher = getattr(sp, name)\nlauncher(['x'])\n")
    discovery = harness.discover_repository(root)
    assert discovery["status"] == "REFUTED"
    assert any(issue["code"] == "DYNAMIC_PROCESS_CALLEE" for issue in discovery["issues"])
    assert harness.assess_repository(root, ())["status"] == "REFUTED"


@pytest.mark.parametrize("source", [
    (
        "import subprocess\n"
        "launcher = subprocess.run\n"
        "if enabled:\n"
        "    launcher = lambda *args: None\n"
        "launcher(['x'])\n"
    ),
    (
        "import subprocess\n"
        "launcher = subprocess.run if enabled else (lambda *args: None)\n"
        "launcher(['x'])\n"
    ),
])
def test_conditionally_rebound_process_alias_refutes_instead_of_disappearing(
        tmp_path: Path, source: str) -> None:
    discovery = harness.discover_repository(repository(tmp_path, source))
    assert discovery["status"] == "REFUTED"
    assert any(issue["code"] == "DYNAMIC_PROCESS_CALLEE"
               for issue in discovery["issues"])


@pytest.mark.parametrize("source", [
    (
        "import multiprocessing as mp\n"
        "mp.Process(target=lambda: None).start()\n"
    ),
    (
        "from multiprocessing import Process\n"
        "child = Process(target=lambda: None)\n"
        "child.start()\n"
    ),
])
def test_multiprocessing_process_start_is_explicitly_outside_the_denominator(
        tmp_path: Path, source: str) -> None:
    discovery = harness.discover_repository(repository(tmp_path, source))
    assert discovery["status"] == "REFUTED"
    issue = next(issue for issue in discovery["issues"]
                 if issue["code"] == "UNSUPPORTED_PROCESS_FAMILY")
    assert "multiprocessing.Process.start" in issue["detail"]
    assert "not exhaustive" in discovery["claim_boundary"]


def test_unknown_subprocess_api_is_explicit_unsupported_ambiguity(tmp_path: Path) -> None:
    root = repository(tmp_path, "import subprocess\nsubprocess.future_launch(['x'])\n")
    discovery = harness.discover_repository(root)
    assert discovery["status"] == "REFUTED"
    assert any(issue["code"] == "UNSUPPORTED_PROCESS_API"
               for issue in discovery["issues"])


def test_unparsed_source_is_explicit_ambiguity(tmp_path: Path) -> None:
    root = repository(tmp_path, "import subprocess\ndef broken(:\n")
    discovery = harness.discover_repository(root)
    assert discovery["status"] == "REFUTED"
    issue = next(issue for issue in discovery["issues"]
                 if issue["code"] == "PYTHON_SOURCE_UNPARSEABLE")
    assert issue["path"] == "src/verifier/sample.py"
    assert type(issue["line"]) is int


@pytest.mark.parametrize(("field", "value", "code"), [
    ("necessity_reason", " ", "DECLARATION_REASON_REQUIRED"),
    ("observation_disposition", "ASSUMED", "DECLARATION_DISPOSITION_INVALID"),
    ("unobserved_gaps", [], "DECLARATION_GAPS_REQUIRED"),
])
def test_reason_disposition_and_unobserved_gaps_are_mandatory(
        tmp_path: Path, field: str, value: object, code: str) -> None:
    root = repository(tmp_path, "import subprocess\nsubprocess.run(['x'])\n")
    baseline = list(declared(root))
    baseline[0] = deepcopy(baseline[0])
    baseline[0][field] = value
    report = harness.assess_repository(root, baseline)
    assert report["status"] == "REFUTED"
    assert code in finding_codes(report)


def test_worker_must_be_one_literal_and_is_never_executed(tmp_path: Path) -> None:
    root = repository(tmp_path, "", "WORKER = make_worker()\n")
    discovery = harness.discover_repository(root)
    assert discovery["status"] == "REFUTED"
    assert discovery["launch_count"] == 0
    assert any(issue["code"] == "EMBEDDED_WORKER_LITERAL_UNAVAILABLE"
               for issue in discovery["issues"])


def test_unselected_third_party_root_is_not_scanned_or_refuted(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    declaration = {"objects": [{"object_id": "generic", "kind": "OBJECT",
        "specializations": [], "surfaces": [harness.SELECTION_SURFACE]}]}
    classified = [{"object_id": "generic", "declared_kinds": ["OBJECT"],
                   "effective_kinds": ["OBJECT", "HARNESS"]}]
    monkeypatch.setattr(harness, "discover_repository",
        lambda *args, **kwargs: pytest.fail("an unselected third-party root must not be scanned"))
    report = harness.assess_selected_repository(tmp_path, declaration, classified)
    assert report["selection_status"] == report["status"] == "NOT_SELECTED"
    assert report["owner_object_id"] is None and report["findings"] == []
    assert report["blockers"] == []
    assert report["report_digest"] == harness.report_digest(report)


def test_selected_harness_owner_runs_the_self_only_checker(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    declaration = {"objects": [{"object_id": "selected-harness", "kind": "HARNESS",
        "specializations": [], "surfaces": [harness.SELECTION_SURFACE]}]}
    classified = [{"object_id": "selected-harness", "declared_kinds": ["HARNESS"],
                   "effective_kinds": ["HARNESS"]}]
    calls: list[Path] = []

    def passing(root: Path) -> dict:
        calls.append(Path(root))
        return {"status": "PASS", "findings": [], "claim_boundary": harness.CLAIM_BOUNDARY}

    monkeypatch.setattr(harness, "assess_repository", passing)
    report = harness.assess_selected_repository(tmp_path, declaration, classified)
    assert calls == [tmp_path]
    assert report["selection_status"] == "SELECTED"
    assert report["owner_object_id"] == "selected-harness"
    assert report["status"] == "PASS" and report["blockers"] == []
    assert report["execution_established"] is False
    assert report["confinement_established"] is False
    assert report["harness_conformance_established"] is False


def test_selected_harness_uses_manifest_owned_launch_denominator(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = repository(
        tmp_path,
        "import subprocess\ndef launch():\n    subprocess.run(['one'])\n",
    )
    baseline = declared(root)
    declaration = {"objects": [{
        "object_id": "selected-harness",
        "kind": "HARNESS",
        "specializations": [],
        "surfaces": [harness.SELECTION_SURFACE],
        "payload": {
            "direct_launch_denominator": harness.denominator_document(baseline),
        },
    }]}
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", ())

    report = harness.assess_selected_repository(root, declaration)

    assert report["owner_object_id"] == "selected-harness"
    assert report["status"] == "PASS", report["findings"]
    assert report["declared_launch_count"] == len(baseline)


def test_one_owner_may_accumulate_harness_with_another_declared_role(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    declaration = {"objects": [{"object_id": "multi-role-owner", "kind": "HARNESS",
        "specializations": ["OBJECT"], "surfaces": [harness.SELECTION_SURFACE]}]}
    classified = [{"object_id": "multi-role-owner",
                   "declared_kinds": ["HARNESS", "OBJECT"]}]
    calls: list[Path] = []

    def passing(root: Path) -> dict:
        calls.append(Path(root))
        return {"status": "PASS", "findings": [], "claim_boundary": harness.CLAIM_BOUNDARY}

    monkeypatch.setattr(harness, "assess_repository", passing)
    report = harness.assess_selected_repository(tmp_path, declaration, classified)
    assert calls == [tmp_path]
    assert report["selection_status"] == "SELECTED"
    assert report["owner_object_id"] == "multi-role-owner"
    assert report["status"] == "PASS" and report["findings"] == []


@pytest.mark.parametrize("objects", [
    [
        {"object_id": "selected-harness", "kind": "HARNESS",
         "specializations": [], "surfaces": [harness.SELECTION_SURFACE]},
        {"object_id": "also-owner", "kind": "OBJECT",
         "specializations": [], "surfaces": [harness.SELECTION_SURFACE]},
    ],
    [
        {"object_id": "first-harness-role", "kind": "HARNESS",
         "specializations": ["OBJECT"], "surfaces": [harness.SELECTION_SURFACE]},
        {"object_id": "second-owner", "kind": "HARNESS",
         "specializations": [], "surfaces": [harness.SELECTION_SURFACE]},
    ],
])
def test_selection_refuses_multiple_checker_surface_owners(
        tmp_path: Path, objects: list[dict],
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "assess_repository",
        lambda *args, **kwargs: pytest.fail("invalid ownership must prevent assessment"))
    report = harness.assess_selected_repository(tmp_path, {"objects": objects})
    assert report["selection_status"] == "SELECTED"
    assert report["status"] == "FAIL"
    assert report["owner_object_id"] is None
    assert "SELECTION_OWNER_AMBIGUOUS" in finding_codes(report)
    mapped = harness.integration_findings(report)
    assert [row["status"] for row in mapped] == ["FAIL"]
    assert [row["coordinate"] for row in mapped] == ["VSTD-T0.2"]


@pytest.mark.parametrize(("unreadable_relative", "expected_issue"), [
    ("src/verifier/sample.py", "PYTHON_SOURCE_UNREADABLE"),
    (harness.EMBEDDED_WORKER_PATH, "EMBEDDED_WORKER_CONTAINER_UNREADABLE"),
])
def test_unreadable_selected_source_is_unknown_without_synthesized_missing_sites(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        unreadable_relative: str, expected_issue: str) -> None:
    root = repository(tmp_path, "import subprocess\nsubprocess.run(['x'])\n")
    baseline = declared(root)
    unreadable = root / unreadable_relative
    original_read_bytes = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        if path == unreadable:
            raise PermissionError("fixture source denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(harness, "PACKAGE_LAUNCH_DECLARATIONS", baseline)
    declaration = {"objects": [{"object_id": "selected-harness", "kind": "HARNESS",
        "specializations": [], "surfaces": [harness.SELECTION_SURFACE]}]}
    report = harness.assess_selected_repository(root, declaration)
    assert report["selection_status"] == "SELECTED"
    assert report["status"] == "UNKNOWN"
    assert finding_codes(report) == {"DISCOVERY_AMBIGUITY"}
    assert "DECLARED_DIRECT_LAUNCH_MISSING" not in finding_codes(report)
    issue = report["findings"][0]["issue"]
    assert issue["code"] == expected_issue
    mapped = harness.integration_findings(report)
    assert [(row["status"], row["coordinate"], row["blocker"]) for row in mapped] == [
        ("UNKNOWN", "VSTD-T0.7", "PACKAGE_HARNESS_APPLICABILITY_UNAVAILABLE")]


@pytest.mark.parametrize(("finding", "coordinate", "status", "blocker"), [
    ({"code": "UNDECLARED_DIRECT_LAUNCH", "launch_id": "new"}, "VSTD-T0.2", "FAIL",
     "PACKAGE_HARNESS_APPLICABILITY_DENOMINATOR_REFUTED"),
    ({"code": "DIRECT_LAUNCH_SOURCE_CHANGED", "launch_id": "changed"}, "VSTD-T0.7", "FAIL",
     "PACKAGE_HARNESS_APPLICABILITY_SOURCE_DRIFT"),
    ({"code": "DISCOVERY_AMBIGUITY", "issue": {"code": "PYTHON_SOURCE_UNREADABLE"}},
     "VSTD-T0.7", "UNKNOWN", "PACKAGE_HARNESS_APPLICABILITY_UNAVAILABLE"),
])
def test_integration_mapping_preserves_denominator_drift_and_unavailability(
        finding: dict, coordinate: str, status: str, blocker: str) -> None:
    mapped = harness.integration_findings({"selection_status": "SELECTED",
        "owner_object_id": "selected-harness", "findings": [finding]})
    assert len(mapped) == 1
    assert mapped[0]["coordinate"] == coordinate
    assert mapped[0]["status"] == status
    assert mapped[0]["blocker"] == blocker


# --- MODEL corrigibility isolated worker: reviewed launch ------------------------------
#
# The launch starts one fixed, installed worker in a fresh interpreter.  The catalog row
# binds the launching call; these tests bind what the review of the *worker* relied on,
# so a later edit that widens the worker fails here and forces a new review instead of
# riding on the old one.

WORKER_RELATIVE = "src/verifier/domains/contracts/model_corrigibility_worker.py"
REVIEWED_WORKER_IMPORTS = frozenset(
    {"__future__", "base64", "hashlib", "hmac", "json", "sys", "typing"})
# Names whose use would give the worker a process, file, network, dynamic-code or
# environment effect that the review did not cover.
FORBIDDEN_WORKER_NAMES = frozenset({
    "open", "eval", "exec", "compile", "__import__", "input", "breakpoint", "getattr",
    "setattr", "globals", "locals", "vars", "importlib", "os", "subprocess", "socket",
    "ctypes", "shutil", "pathlib", "urllib", "http", "multiprocessing", "threading",
    "asyncio", "pickle", "marshal", "tempfile",
})
REVIEWED_STDIO_ATTRIBUTES = frozenset({"stdin", "stdout", "stderr", "buffer", "read", "write"})


def worker_boundary_violations(source: str) -> list[str]:
    """Return every import, name, or ``sys`` attribute outside the reviewed boundary."""

    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            violations += [f"import {alias.name}" for alias in node.names
                           if alias.name.split(".")[0] not in REVIEWED_WORKER_IMPORTS]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in REVIEWED_WORKER_IMPORTS:
                violations.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_WORKER_NAMES:
            violations.append(f"name {node.id}")
        elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "sys" and node.attr not in REVIEWED_STDIO_ATTRIBUTES):
            violations.append(f"sys.{node.attr}")
    return sorted(set(violations))


def test_model_corrigibility_launch_is_reviewed_with_a_recorded_reason() -> None:
    row = _catalog_by_id()[MODEL_CORRIGIBILITY_ID]
    assert row["path"] == "src/verifier/domains/contracts/model_corrigibility.py"
    assert row["callee"] == "subprocess.run" and row["embedded_name"] is None
    assert row["observation_disposition"] == "SOURCE_ENUMERATION_ONLY"
    reason = row["necessity_reason"]
    assert "fresh isolated" in reason and "model_corrigibility_worker.py" in reason
    # The launch inherits the parent environment apart from two removed variables, and
    # the launcher's own bounds are not a claim about the child; both stay unobserved.
    assert "inherited-environment" in row["unobserved_gaps"]
    assert set(harness.DEFAULT_UNOBSERVED) <= set(row["unobserved_gaps"])


def test_model_corrigibility_launch_is_a_fixed_isolated_argv_without_a_shell() -> None:
    function = _top_level_function(
        "src/verifier/domains/contracts/model_corrigibility.py", "_invoke_worker")
    call = next(node for node in ast.walk(function)
                if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.run")
    argv = call.args[0]
    assert isinstance(argv, ast.List)
    assert [ast.unparse(item) for item in argv.elts] == [
        "sys.executable", "'-I'", "'-S'", "'-B'", "'-u'", "str(worker)"]
    keywords = {keyword.arg for keyword in call.keywords}
    assert "shell" not in keywords
    assert {"timeout", "env", "cwd", "input"} <= keywords
    check = next(keyword.value for keyword in call.keywords if keyword.arg == "check")
    assert isinstance(check, ast.Constant) and check.value is False


def test_model_corrigibility_worker_stays_inside_the_reviewed_pure_boundary() -> None:
    source = (ROOT / WORKER_RELATIVE).read_text(encoding="utf-8")
    assert worker_boundary_violations(source) == []


@pytest.mark.parametrize("added, expected", (
    ("import subprocess\n", "import subprocess"),
    ("import socket\n", "import socket"),
    ("from os import system\n", "from os import ..."),
    ("open('x')\n", "name open"),
    ("exec('x')\n", "name exec"),
    ("sys.exit(1)\n", "sys.exit"),
    ("sys.modules\n", "sys.modules"),
))
def test_worker_boundary_check_flags_each_capability_the_review_excluded(
        added: str, expected: str) -> None:
    source = (ROOT / WORKER_RELATIVE).read_text(encoding="utf-8")
    assert expected in worker_boundary_violations(added + source)
