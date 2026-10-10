"""Preparation workflow controls; no publication or behavioral qualification.

JavaScript Object Notation (JSON); Pull Request Domain Explanation Language (PRDEL).
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from verifier.runtime import polish_workflow as workflow
from verifier.runtime import quality_checks


def policy(paths: list[str], *selected: str) -> dict:
    selected_set = {"bind-inputs", "validate-definitions", "retain-bundle", *selected}
    return {
        "schema_version": workflow.POLICY_SCHEMA,
        "input_paths": paths,
        "stages": [
            {
                "id": row["id"],
                "selected": row["id"] in selected_set,
                "required": row["id"] in selected_set,
                "depends_on": row["depends_on"],
            }
            for row in workflow.STAGES
        ],
        "bounds": {"max_files": 16, "max_file_bytes": 8192, "max_total_bytes": 65536},
    }


def invoke(root: Path, value: dict, **kwargs: object) -> dict:
    raw = workflow.canonical(value)
    return workflow.prepare_workflow(
        root, policy_bytes=raw, expected_policy_digest=workflow.digest(raw), **kwargs
    )


def definitions() -> bytes:
    return workflow.canonical(
        {
            "schema_version": "verifier-explanation-definitions-1",
            "definitions": [
                {
                    "id": "increment.intent",
                    "target": {"path": "demo.py", "symbol": "increment"},
                    "intent": "Expose a finite increment operation.",
                    "requirement_ids": [],
                    "invariants": [],
                    "limits": ["Authored intent does not establish correctness."],
                }
            ],
        }
    )


def profile() -> bytes:
    return workflow.canonical(
        {
            "schema_version": "verifier-quality-profile-1",
            "sources": ["demo.py"],
            "stages": [
                {
                    "id": name,
                    "selected": name == "comment-format",
                    "required": name == "comment-format",
                    "backend": (
                        "builtin-managed-python-comments-1"
                        if name == "comment-format"
                        else None
                    ),
                    "tool": None,
                    "config": None,
                }
                for name in quality_checks.STAGES
            ],
            "timeout_seconds": 2,
            "max_output_bytes": 4096,
        }
    )


def fixture(root: Path) -> bytes:
    root.mkdir()
    raw = b"# handwritten comment\ndef increment(x):\n    return x + 1\n"
    (root / "demo.py").write_bytes(raw)
    return raw


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def git_fixture(root: Path) -> tuple[str, str]:
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    (root / "README.md").write_bytes(b"Before exact text.\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Baseline")
    base = git(root, "rev-parse", "HEAD")
    (root / "README.md").write_bytes(b"After exact text.\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Change")
    return base, git(root, "rev-parse", "HEAD")


def test_check_only_projection_and_bundle_are_byte_deterministic(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    raw = profile()
    value = policy(["demo.py"], "project-comments", "quality")
    options = {
        "definition_bytes": definitions(),
        "quality_profile_bytes": raw,
        "expected_quality_profile_digest": workflow.digest(raw),
        "output": tmp_path / "retained",
    }
    first = invoke(root, value, **options)
    second = invoke(root, value, **options)
    assert first["status"] == second["status"] == "PASS"
    assert first["polished"] is first["promotable"] is False
    assert (root / "demo.py").read_bytes() == before
    assert first["state"] == "PREPARED_PENDING_COMMIT"
    assert first["bundle"]["id"] == second["bundle"]["id"]
    bundle = Path(first["bundle"]["path"])
    prepared = (bundle / "source/demo.py").read_bytes()
    assert b"# handwritten comment" in prepared
    assert prepared.count(b"# vstd-explanation: begin increment.intent") == 1
    assert (
        b"Expose a finite increment"
        in (bundle / "description.prepared.md").read_bytes()
    )
    assert "manifest.json" not in {
        row["path"] for row in first["bundle"]["manifest"]["payload"]["files"]
    }
    assert len(list((tmp_path / "retained/attempts").glob("*.json"))) == 1
    assert len(list((tmp_path / "retained/journal").glob("*.json"))) == 4


def test_explicit_apply_idempotence_and_safe_rollback(tmp_path: Path) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    value = policy(["demo.py"], "project-comments")
    options = {
        "definition_bytes": definitions(),
        "output": tmp_path / "retained",
        "apply": True,
    }
    first = invoke(root, value, **options)
    assert first["status"] == "PASS" and first["evidence_invalidated"] is True
    prepared = (root / "demo.py").read_bytes()
    second = invoke(root, value, **options)
    assert second["status"] == "PASS" and second["evidence_invalidated"] is False
    assert (root / "demo.py").read_bytes() == prepared
    assert first["bundle"]["id"] == second["bundle"]["id"]
    result = workflow.recover_apply(root, first["apply_plan"], rollback=True)
    assert result["status"] == "PASS"
    assert (root / "demo.py").read_bytes() == before
    assert workflow.recover_apply(root, first["apply_plan"])["status"] == "PASS"
    assert (root / "demo.py").read_bytes() == prepared


def test_later_edit_blocks_rollback_without_clobber(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    result = invoke(
        root,
        policy(["demo.py"], "project-comments"),
        definition_bytes=definitions(),
        output=tmp_path / "retained",
        apply=True,
    )
    later = (root / "demo.py").read_bytes() + b"# later user work\n"
    (root / "demo.py").write_bytes(later)
    with pytest.raises(workflow.WorkflowError, match="later source edit"):
        workflow.recover_apply(root, result["apply_plan"], rollback=True)
    assert (root / "demo.py").read_bytes() == later


def test_quality_failure_stop_and_changed_source_resume(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    malformed = (
        b"# vstd-explanation: end missing\ndef increment(x):\n    return x + 1\n"
    )
    (root / "demo.py").write_bytes(malformed)
    value = policy(["demo.py"], "quality")
    raw = profile()
    options = {
        "quality_profile_bytes": raw,
        "expected_quality_profile_digest": workflow.digest(raw),
        "output": tmp_path / "retained",
    }
    failed = invoke(root, value, **options)
    assert failed["status"] == "FAIL" and failed["bundle"] is None
    assert (root / "demo.py").read_bytes() == malformed
    stages = {row["id"]: row for row in failed["stages"]}
    assert stages["quality"]["status"] == "FAIL"
    assert stages["retain-bundle"]["execution_status"] == "NOT_RUN"
    (root / "demo.py").write_bytes(b"def increment(x):\n    return x + 1\n")
    resumed = invoke(root, value, resume=failed, **options)
    assert resumed["status"] == "PASS"
    assert resumed["resume"]["identity_matches"] is False
    assert "quality" in resumed["resume"]["invalidated_stages"]
    assert resumed["resume"]["reused_stages"] == []
    assert len(list((tmp_path / "retained/attempts").glob("*.json"))) == 2


def test_same_input_resume_rechecks_instead_of_trusting_carried_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    fixture(root)
    value = policy(["demo.py"], "quality")
    raw = profile()
    options = {
        "quality_profile_bytes": raw,
        "expected_quality_profile_digest": workflow.digest(raw),
    }
    first = invoke(root, value, **options)
    calls: list[bool] = []
    real = quality_checks.run_quality_profile

    def observed(*args: object, **kwargs: object) -> dict:
        calls.append(True)
        return real(*args, **kwargs)

    monkeypatch.setattr(quality_checks, "run_quality_profile", observed)
    second = invoke(root, value, resume=first, **options)
    assert second["status"] == "PASS" and calls == [True]
    assert second["resume"]["identity_matches"] is True
    assert second["resume"]["reused_stages"] == []


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "cycle",
        "publish",
        "hook",
        "env",
        "unselected-required",
        "prerequisite",
        "path-traversal",
        "path-git",
        "path-case",
        "bound",
        "policy-pin",
    ],
)
def test_known_policy_violations_fail_before_source_work(
    tmp_path: Path, change: str
) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    value = policy(["demo.py"])
    if change == "duplicate":
        value["stages"][1]["id"] = "bind-inputs"
    elif change == "cycle":
        value["stages"][0]["depends_on"] = ["retain-bundle"]
    elif change == "publish":
        value["stages"][1]["id"] = "publish"
    elif change == "hook":
        value["stages"][0]["command"] = ["publish"]
    elif change == "env":
        value["environment"] = {"TOKEN": "not authorized"}
    elif change == "unselected-required":
        value["stages"][0]["selected"] = False
    elif change == "prerequisite":
        value["stages"][1]["depends_on"] = []
    elif change == "path-traversal":
        value["input_paths"] = ["../demo.py"]
    elif change == "path-git":
        value["input_paths"] = [".git/config"]
    elif change == "path-case":
        value["input_paths"] = ["demo.py", "DEMO.py"]
    elif change == "bound":
        value["bounds"]["max_total_bytes"] = 0
    raw = workflow.canonical(value)
    result = workflow.prepare_workflow(
        root,
        policy_bytes=raw,
        expected_policy_digest=(
            "0" * 64 if change == "policy-pin" else workflow.digest(raw)
        ),
    )
    assert result["status"] == "FAIL" and result["stages"] == []
    assert (root / "demo.py").read_bytes() == before


def test_missing_required_definition_or_quality_is_known_failure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    projected = invoke(root, policy(["demo.py"], "project-comments"))
    assert projected["status"] == "FAIL"
    checked = invoke(root, policy(["demo.py"], "quality"))
    assert checked["status"] == "FAIL"
    assert (root / "demo.py").read_bytes() == before


def test_output_within_source_and_apply_without_journal_are_refused(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    assert invoke(root, policy(["demo.py"]), output=root / "output")["status"] == "FAIL"
    assert invoke(root, policy(["demo.py"]), apply=True)["status"] == "FAIL"
    assert not (root / "output").exists()
    assert (root / "demo.py").read_bytes() == before


def test_source_edit_during_quality_is_retained_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    fixture(root)
    later = b"# new user edit\ndef increment(x):\n    return x + 2\n"

    def changed(*args: object, **kwargs: object) -> dict:
        (root / "demo.py").write_bytes(later)
        return {"status": "PASS"}

    monkeypatch.setattr(quality_checks, "run_quality_profile", changed)
    raw = profile()
    result = invoke(
        root,
        policy(["demo.py"], "quality"),
        quality_profile_bytes=raw,
        expected_quality_profile_digest=workflow.digest(raw),
        apply=True,
        output=tmp_path / "retained",
    )
    assert result["status"] == "FAIL" and result["bundle"] is None
    assert (root / "demo.py").read_bytes() == later


def test_cancelled_quality_is_unknown_and_source_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    before = fixture(root)

    def cancelled(*args: object, **kwargs: object) -> dict:
        raise KeyboardInterrupt()

    monkeypatch.setattr(quality_checks, "run_quality_profile", cancelled)
    raw = profile()
    result = invoke(
        root,
        policy(["demo.py"], "quality"),
        quality_profile_bytes=raw,
        expected_quality_profile_digest=workflow.digest(raw),
        output=tmp_path / "retained",
    )
    assert result["status"] == "UNKNOWN" and result["bundle"] is None
    assert (root / "demo.py").read_bytes() == before
    assert any(f["code"] == "PREPARATION_CANCELLED" for f in result["findings"])


def test_immutable_bundle_tampering_cannot_be_overwritten(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    value = policy(["demo.py"])
    first = invoke(root, value, output=tmp_path / "retained")
    bundle = Path(first["bundle"]["path"])
    (bundle / "source/demo.py").write_bytes(b"tampered\n")
    second = invoke(root, value, output=tmp_path / "retained")
    assert second["status"] == "FAIL"
    assert (bundle / "source/demo.py").read_bytes() == b"tampered\n"


def test_tampered_resume_does_not_reuse_clearance(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    value = policy(["demo.py"])
    first = invoke(root, value)
    first["status"] = "UNKNOWN"
    second = invoke(root, value, resume=first)
    assert second["status"] == "FAIL"
    assert second["resume"]["reused_stages"] == []


def test_bounded_narrative_diff_positive_and_exact_commit_association(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    base, head = git_fixture(root)
    value = policy(["README.md"], "compile-explanations")
    result = invoke(
        root, value, git_root=root, base=base, head=head, output=tmp_path / "retained"
    )
    assert result["status"] == "PASS", result
    assert result["verification"]["status"] == "PASS"
    assert set(result["verification"]["coverage"]["layers"]) == {
        "base",
        "unit",
        "integration",
        "regression",
        "preventative",
    }
    bundle = Path(result["bundle"]["path"])
    assert (bundle / "description.committed.pr.md").is_file()
    assert (bundle / "compilation.json").is_file()
    associated = workflow.associate_commit(root, result["bundle"]["manifest"], head)
    assert associated["status"] == "PASS"
    assert (
        workflow.associate_commit(root, result["bundle"]["manifest"], base)["status"]
        == "FAIL"
    )
    assert (
        workflow.associate_commit(root, result["bundle"]["manifest"], "HEAD")["status"]
        == "FAIL"
    )


def test_uncommitted_source_cannot_claim_committed_explanation(tmp_path: Path) -> None:
    root = tmp_path / "source"
    base, head = git_fixture(root)
    later = b"Later uncommitted bytes.\n"
    (root / "README.md").write_bytes(later)
    result = invoke(
        root,
        policy(["README.md"], "compile-explanations"),
        git_root=root,
        base=base,
        head=head,
    )
    assert result["status"] == "FAIL" and result["bundle"] is None
    assert result["commit_correspondence"]["input_matches_selected_head"] is False
    assert (root / "README.md").read_bytes() == later


def test_whole_tree_association_rejects_omitted_file_or_mode(tmp_path: Path) -> None:
    root = tmp_path / "source"
    base, head = git_fixture(root)
    result = invoke(
        root,
        policy(["README.md"], "compile-explanations"),
        git_root=root,
        base=base,
        head=head,
    )
    manifest = copy.deepcopy(result["bundle"]["manifest"])
    manifest["git_modes"]["README.md"] = "100755"
    assert workflow.associate_commit(root, manifest, head)["status"] == "FAIL"
    manifest["git_modes"] = None
    assert workflow.associate_commit(root, manifest, head)["status"] == "UNKNOWN"
    manifest["source"]["files"] = []
    assert workflow.associate_commit(root, manifest, head)["status"] == "FAIL"


def test_apply_plan_tampering_and_partial_apply_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    (root / "other.py").write_bytes(b"def other(x):\n    return x\n")
    raw_definition = json.loads(definitions())
    other = copy.deepcopy(raw_definition["definitions"][0])
    other.update(id="other.intent", target={"path": "other.py", "symbol": "other"})
    raw_definition["definitions"].append(other)
    real = workflow._replace
    calls: list[bool] = []

    def interrupt_second(target: Path, old: bytes, new: bytes) -> None:
        calls.append(True)
        if len(calls) == 2:
            raise OSError("fixture write interruption")
        real(target, old, new)

    monkeypatch.setattr(workflow, "_replace", interrupt_second)
    result = invoke(
        root,
        policy(["demo.py", "other.py"], "project-comments"),
        definition_bytes=workflow.canonical(raw_definition),
        output=tmp_path / "retained",
        apply=True,
    )
    assert result["status"] != "PASS"
    assert (root / "demo.py").read_bytes() == before
    assert (root / "other.py").read_bytes() == b"def other(x):\n    return x\n"
    plan = next((tmp_path / "retained/apply-plans").glob("*.json"))
    value = json.loads(plan.read_bytes())
    value["files"][0]["path"] = "../outside.py"
    plan.write_bytes(workflow.canonical(value))
    with pytest.raises(workflow.WorkflowError, match="binding mismatch"):
        workflow.recover_apply(root, plan)


def test_hard_link_source_refused_without_mutation(tmp_path: Path) -> None:
    root = tmp_path / "source"
    before = fixture(root)
    os.link(root / "demo.py", tmp_path / "alias.py")
    result = invoke(root, policy(["demo.py"]))
    assert result["status"] == "FAIL"
    assert (tmp_path / "alias.py").read_bytes() == before


def test_prepared_comments_associate_with_later_exact_git_tree(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Original source")
    head = git(root, "rev-parse", "HEAD")
    result = invoke(
        root,
        policy(["demo.py"], "project-comments"),
        definition_bytes=definitions(),
        git_root=root,
        head=head,
        base=head,
        apply=True,
        output=tmp_path / "retained",
    )
    assert result["status"] == "PASS"
    assert (
        result["bundle"]["manifest"]["preparation_state"] == "PREPARED_PENDING_COMMIT"
    )
    assert result["bundle"]["manifest"]["committed_analysis_binding"] is None
    assert result["commit_correspondence"]["prepared_matches_selected_head"] is False
    git(root, "add", ".")
    git(root, "commit", "-qm", "Retained prepared source")
    later = git(root, "rev-parse", "HEAD")
    assert (
        workflow.associate_commit(root, result["bundle"]["manifest"], later)["status"]
        == "PASS"
    )
    assert (
        workflow.associate_commit(root, result["bundle"]["manifest"], head)["status"]
        == "FAIL"
    )
    assert result["bundle"]["manifest"]["git_binding"]["head"] == head


def test_resume_bundle_rehashes_payload_and_refuses_extra_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    fixture(root)
    value = policy(["demo.py"])
    first = invoke(root, value, output=tmp_path / "retained")
    resumed = invoke(root, value, resume=first["bundle"]["path"])
    assert resumed["status"] == "PASS" and resumed["resume"]["reused_stages"] == []
    bundle = Path(first["bundle"]["path"])
    (bundle / "source/demo.py").write_bytes(b"changed\n")
    assert invoke(root, value, resume=bundle)["status"] == "FAIL"
    manifest = copy.deepcopy(first["bundle"]["manifest"])
    manifest["publish"] = True
    assert invoke(root, value, resume=manifest)["status"] == "FAIL"


def test_definition_change_after_provenance_is_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from verifier.runtime import explanation_projection

    root = tmp_path / "source"
    fixture(root)
    selected = definitions()
    (root / "definition.json").write_bytes(selected)
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Selected definitions")
    head = git(root, "rev-parse", "HEAD")

    def changed(*args: object, **kwargs: object) -> dict:
        (root / "definition.json").write_bytes(b"{}")
        return {"status": "UNKNOWN", "workspace_sha256": workflow.digest(selected)}

    monkeypatch.setattr(
        explanation_projection, "resolve_definition_provenance", changed
    )
    result = invoke(
        root,
        policy(["demo.py"], "project-comments"),
        definition_bytes=selected,
        definition_path="definition.json",
        git_root=root,
        head=head,
    )
    assert result["status"] == "FAIL" and result["bundle"] is None
    assert (root / "definition.json").read_bytes() == b"{}"


def test_missing_git_observation_preserves_unknown_stage(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    result = invoke(root, policy(["demo.py"]), git_root=root, head="0" * 40)
    stages = {row["id"]: row for row in result["stages"]}
    assert stages["bind-inputs"]["status"] == "UNKNOWN"
    assert stages["retain-bundle"]["execution_status"] == "NOT_RUN"
    assert result["bundle"] is None


def test_workflow_policy_does_not_silently_select_quality_tool(tmp_path: Path) -> None:
    root = tmp_path / "source"
    fixture(root)
    raw = profile()
    result = invoke(
        root,
        policy(["demo.py"], "quality"),
        quality_profile_bytes=raw,
        expected_quality_profile_digest="0" * 64,
    )
    assert result["status"] == "FAIL" and result["stages"] == []


def test_quality_bundle_projection_preserves_outcomes_without_temporary_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    fixture(root)
    raw = profile()
    real = quality_checks.run_quality_profile
    invocations = []

    def operational(staged: Path, *args: object) -> dict:
        result = real(staged, *args)
        result["stages"][0]["invocation"] = [str(staged / "demo.py")]
        invocations.append(str(staged))
        return result

    monkeypatch.setattr(quality_checks, "run_quality_profile", operational)
    options = {
        "quality_profile_bytes": raw,
        "expected_quality_profile_digest": workflow.digest(raw),
        "output": tmp_path / "retained",
    }
    first = invoke(root, policy(["demo.py"], "quality"), **options)
    second = invoke(root, policy(["demo.py"], "quality"), **options)
    assert first["status"] == second["status"] == "PASS"
    assert invocations[0] != invocations[1]
    assert first["bundle"]["id"] == second["bundle"]["id"]
    projected = json.loads(
        (Path(first["bundle"]["path"]) / "quality-observation.json").read_bytes()
    )
    assert projected["observation"]["stages"][0]["status"] == "PASS"
    assert "invocation" not in projected["observation"]["stages"][0]
    attempts = [
        json.loads(path.read_bytes())
        for path in (tmp_path / "retained/attempts").glob("*.json")
    ]
    assert len(attempts) == 2
    assert all("invocation" in attempt["quality"]["stages"][0] for attempt in attempts)


def test_quality_environment_change_invalidates_resume_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    fixture(root)
    raw = profile()
    options = {
        "quality_profile_bytes": raw,
        "expected_quality_profile_digest": workflow.digest(raw),
    }
    first = invoke(root, policy(["demo.py"], "quality"), **options)
    original = quality_checks._environment
    monkeypatch.setattr(
        quality_checks,
        "_environment",
        lambda: {**original(), "TEMP": "different-admitted-environment"},
    )
    second = invoke(root, policy(["demo.py"], "quality"), resume=first, **options)
    assert second["status"] == "PASS"
    assert second["resume"]["identity_matches"] is False
    assert "quality" in second["resume"]["invalidated_stages"]
