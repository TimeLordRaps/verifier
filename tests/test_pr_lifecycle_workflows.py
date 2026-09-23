"""Terminology: identifier (ID); operating system (OS); Secure Hash Algorithm 256-bit (SHA-256).

Repository-process tests for pull-request promotion and delivery.
"""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_privileged_policy_uses_default_branch_wakeups_only() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-policy.yml").read_text(encoding="utf-8"))
    events = workflow.get("on", workflow.get(True))
    assert "pull_request_review" not in events
    assert "merge_group" not in events
    assert events["workflow_run"]["types"] == ["requested", "completed"]
    assert "statuses" not in workflow["permissions"]
    for job in workflow["jobs"].values():
        if job.get("permissions", {}).get("statuses") == "write":
            assert "workflow_run" in job["if"] or "needs.notification" in job["if"]
    notification = yaml.safe_load((ROOT / ".github/workflows/pr-policy-notification.yml").read_text(encoding="utf-8"))
    assert notification["permissions"] == {}
    assert set(notification.get("on", notification.get(True))) == {"pull_request_review", "merge_group"}
    for job in notification["jobs"].values():
        assert not any("uses" in step for step in job["steps"])
        assert all(step.get("run") == ":" for step in job["steps"])


def test_pull_request_policy_is_separate_trusted_exact_head_gate() -> None:
    path = ROOT / ".github/workflows/pr-policy.yml"
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    job = workflow["jobs"]["evaluate-policy"]
    commands = "\n".join(str(step.get("run", "")) for step in job["steps"])
    checkout = next(step for step in job["steps"] if "actions/checkout@" in step.get("uses", ""))

    assert "pull_request_target:" in text
    for event_type in ("opened", "reopened", "synchronize", "edited", "ready_for_review"):
        assert event_type in text
    notifier = (ROOT / ".github/workflows/pr-policy-notification.yml").read_text(encoding="utf-8")
    assert "types: [submitted, edited, dismissed]" in notifier
    assert "types: [created, edited, deleted]" in text
    assert "merge_group:" in notifier
    assert "types: [checks_requested]" in notifier
    assert workflow["permissions"] == {
        "actions": "read",
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    }
    assert job["permissions"]["statuses"] == "write"
    assert checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    assert "pull_request.head.ref" not in text
    assert "check_pr_policy.py" in commands
    assert 'statuses/$HEAD_SHA' in commands
    assert "PR_HEAD_SHA=$HEAD_SHA" in commands
    assert "-f context=pr-policy" in commands
    assert "-f state=pending" in commands
    assert "--ci-coordinate" in commands
    assert "--repository-run" in commands
    assert "--test-evidence-manifest" in commands
    assert "--build-test-evidence-manifest" in commands
    assert "--confirm-current" in commands
    assert "gh run download" in commands
    for artifact_prefix in (
        "artifact-seal",
        "base-contracts",
        "coverage-tests",
        "installed-composition-contracts",
        "platform-python-contracts",
        "scitt-crypto",
    ):
        assert f'--pattern "{artifact_prefix}-$RUN_ID-$RUN_ATTEMPT-*"' in commands
    assert "--paginate" not in commands
    assert "--slurp" not in commands
    assert "reviews?per_page=100" in commands
    assert "comments?per_page=100" in commands
    assert "jq 'length' \"$RUNNER_TEMP/reviews.json\"" in commands
    assert "jq 'length' \"$RUNNER_TEMP/comments.json\"" in commands
    assert "current-reviews.json" in commands
    assert "current-comments.json" in commands
    assert "final-reviews.json" in commands
    assert "final-comments.json" in commands
    assert workflow["concurrency"]["cancel-in-progress"] is True
    upload_index = next(
        index for index, step in enumerate(job["steps"]) if "actions/upload-artifact@" in step.get("uses", "")
    )
    success_index = next(
        index
        for index, step in enumerate(job["steps"])
        if "Publish success only" in step.get("name", "")
    )
    assert upload_index < success_index

    merge_job = workflow["jobs"]["evaluate-merge-group"]
    merge_commands = "\n".join(str(step.get("run", "")) for step in merge_job["steps"])
    merge_checkout = next(
        step for step in merge_job["steps"] if "actions/checkout@" in step.get("uses", "")
    )
    assert merge_checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    assert "check_merge_group_policy.py" in merge_commands
    assert "entries(first:33)" in merge_commands
    assert "--confirm-current" in merge_commands
    assert "-f state=success -f context=pr-policy" in merge_commands
    assert "pull_request.head.ref" not in merge_commands
    for artifact_prefix in (
        "artifact-seal",
        "base-contracts",
        "coverage-tests",
        "installed-composition-contracts",
        "platform-python-contracts",
        "scitt-crypto",
    ):
        assert f'--pattern "{artifact_prefix}-$RUN_ID-$RUN_ATTEMPT-*"' in merge_commands
    merge_upload_index = next(
        index
        for index, step in enumerate(merge_job["steps"])
        if "actions/upload-artifact@" in step.get("uses", "")
    )
    merge_success_index = next(
        index
        for index, step in enumerate(merge_job["steps"])
        if "Publish required merge-group success" in step.get("name", "")
    )
    assert merge_upload_index < merge_success_index
    assert "final-pr-$PR_NUMBER.json" in merge_job["steps"][merge_success_index]["run"]
    assert "final-reviews-$PR_NUMBER.json" in merge_job["steps"][merge_success_index]["run"]
    assert "final-comments-$PR_NUMBER.json" in merge_job["steps"][merge_success_index]["run"]
    assert "final-merge-queue.json" in merge_job["steps"][merge_success_index]["run"]


def test_notification_consumer_never_trusts_notification_outputs_or_conclusion() -> None:
    text = (ROOT / ".github/workflows/pr-policy.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    job = workflow["jobs"]["notification"]
    commands = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert "workflow_run.conclusion" not in text
    assert "actions/runs/$NOTIFICATION_RUN_ID" in commands
    assert "actions/workflows/$WORKFLOW_ID" in commands
    assert "--current-pr" in commands
    assert "--merge-ref" in commands and "--merge-commit" in commands
    assert 'commits/$HEAD_SHA' in commands and 'git/ref/${HEAD_REF#refs/}' in commands
    assert not any("download-artifact" in step.get("uses", "") for step in job["steps"])
    assert "gh run download" not in commands
    assert 'test "$HEAD_SHA" = "$NOTIFICATION_HEAD"' in text


def test_repository_checks_cover_merge_queue_and_publish_skip_reasons() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    base_commands = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["base"]["steps"]
    )
    platform_commands = "\n".join(
        str(step.get("run", ""))
        for step in workflow["jobs"]["platform-python-contracts"]["steps"]
    )

    assert "merge_group:" in text
    assert "coordinate" in workflow["jobs"]["conformance-gate"]["needs"]
    coordinate_commands = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["coordinate"]["steps"]
    )
    assert "record_ci_coordinate.py" in coordinate_commands
    assert "check_release_boundary.py ci-coordinate.json" in coordinate_commands
    assert "scripts.pytest_public_evidence" in base_commands
    assert "--junitxml=base-contracts.xml" in base_commands
    assert "summarize_test_skips.py" in base_commands
    assert "summarize_test_skips.py" in platform_commands
    assert "--append-output \"$GITHUB_STEP_SUMMARY\"" in base_commands
    assert ">> \"$GITHUB_STEP_SUMMARY\"" not in text
    assert "check_release_boundary.py base-contracts.xml" in base_commands
    expected_pytest_jobs = {
        "artifact-seal": ("artifact-seal.xml", "artifact-seal"),
        "base": ("base-contracts.xml", "base-contracts"),
        "coverage": ("coverage-tests.xml", "coverage-tests"),
        "installed-wheel-smoke": (
            "installed-composition-contracts.xml", "installed-composition-contracts",
        ),
        "platform-python-contracts": (
            "platform-contracts.xml",
            "platform-python-contracts",
        ),
        "scitt-crypto": ("scitt-crypto.xml", "scitt-crypto"),
        "logits-constraints": ("logits-constraints.xml", "logits-constraints"),
    }
    observed_pytest_jobs = {
        job_name
        for job_name, job in workflow["jobs"].items()
        if "pytest" in "\n".join(str(step.get("run", "")) for step in job["steps"])
    }
    assert observed_pytest_jobs == set(expected_pytest_jobs)
    for job_name, (report_name, artifact_prefix) in expected_pytest_jobs.items():
        commands = "\n".join(
            str(step.get("run", "")) for step in workflow["jobs"][job_name]["steps"]
        )
        assert "-p scripts.pytest_public_evidence" in commands
        assert f"--junitxml={report_name}" in commands
        assert "check_release_boundary.py" in commands
        assert report_name in commands.split("check_release_boundary.py", 1)[1]
        assert f"summarize_test_skips.py {report_name}" in commands
        assert f"name: {artifact_prefix}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-" in text


def test_cross_platform_skip_summary_uses_its_declared_bash_syntax() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["platform-python-contracts"]
    summaries = [
        step for step in job["steps"]
        if "summarize_test_skips.py" in step.get("run", "")
    ]
    assert len(summaries) == 1
    assert '--append-output "$GITHUB_STEP_SUMMARY"' in summaries[0]["run"]
    # The Windows runner otherwise selects PowerShell, where this is not an
    # environment-variable reference and the output path becomes empty.
    assert summaries[0].get("shell") == "bash"


def test_pages_preview_retains_hidden_files_and_rechecks_downloaded_bytes() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["presentation"]["steps"]
    artifact_name = "pages-preview-${{ github.sha }}"
    upload = next(step for step in steps if step.get("with", {}).get("name") == artifact_name)
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["path"] == "_site"
    assert upload["with"].get("include-hidden-files") is True
    download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {"name": artifact_name, "path": "${{ runner.temp }}/vstd-pages-preview"}
    validation = next(step for step in steps if "--validate-site" in step.get("run", ""))
    assert steps.index(upload) < steps.index(download) < steps.index(validation)
    assert "continue-on-error" not in validation
    assert 'sha256sum _site/deployment-manifest.json' in validation["run"]
    assert 'scripts/check_pages_deployment.py' in validation["run"]
    assert '--validate-site "$RUNNER_TEMP/vstd-pages-preview"' in validation["run"]
    assert '--expected-source-ref "$GITHUB_SHA"' in validation["run"]
    assert '--expected-manifest-sha256 "$MANIFEST_SHA256"' in validation["run"]


def test_pages_waits_for_successful_default_branch_checks_and_observes_live_bytes() -> None:
    path = ROOT / ".github/workflows/pages.yml"
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    prepare = workflow["jobs"]["prepare"]
    build = workflow["jobs"]["build"]
    validate = workflow["jobs"]["validate"]
    deploy = workflow["jobs"]["deploy"]
    observe = workflow["jobs"]["observe"]
    prepare_commands = "\n".join(str(step.get("run", "")) for step in prepare["steps"])
    build_commands = "\n".join(str(step.get("run", "")) for step in build["steps"])
    validate_commands = "\n".join(str(step.get("run", "")) for step in validate["steps"])
    deploy_commands = "\n".join(str(step.get("run", "")) for step in deploy["steps"])
    observe_commands = "\n".join(str(step.get("run", "")) for step in observe["steps"])
    all_commands = "\n".join(
        (prepare_commands, build_commands, validate_commands, deploy_commands, observe_commands)
    )

    assert "workflow_run:" in text
    assert "workflows: [repository-checks]" in text
    assert "workflow_run.conclusion == 'success'" in prepare["if"]
    assert "workflow_run.event == 'push'" in prepare["if"]
    assert "workflow_run.head_branch == github.event.repository.default_branch" in prepare["if"]
    assert "inputs.known_good_source_ref" in prepare["env"]["SOURCE_SHA"]
    assert "check_pages_deployment.py" in all_commands
    assert "--expected-source-ref \"$SOURCE_SHA\"" in all_commands
    assert "--allowed-host \"$PAGES_HOST\"" in observe_commands
    assert prepare["permissions"] == {"actions": "read", "contents": "read"}
    assert "actions/workflows/ci.yml/runs?head_sha=$SOURCE_SHA" in prepare_commands
    assert all_commands.count('test "$SOURCE_SHA" = "$DEFAULT_SHA"') == 4
    assert "github.event_name == 'workflow_dispatch'" not in all_commands
    assert "redeploy-known-good" in prepare_commands
    assert "--validate-rollback-receipt" in prepare_commands
    assert "--deployment-run" in prepare_commands
    assert (
        "--expected-manifest-sha256 \"${{ needs.prepare.outputs.known_good_manifest_sha256 }}\""
        in validate_commands
    )
    assert "--validate-site _site" in validate_commands
    assert "--expected-manifest-sha256 \"${{ needs.validate.outputs.manifest_sha256 }}\"" in observe_commands
    assert "--deployment-workflow-run-id \"$GITHUB_RUN_ID\"" in observe_commands
    assert 'test "$ROLLBACK_CONFIRMATION" = "REDEPLOY_KNOWN_GOOD"' in prepare_commands
    prepare_checkouts = [
        step for step in prepare["steps"] if "actions/checkout@" in step.get("uses", "")
    ]
    build_checkouts = [
        step for step in build["steps"] if "actions/checkout@" in step.get("uses", "")
    ]
    assert [step["with"]["ref"] for step in prepare_checkouts] == [
        "${{ github.event.repository.default_branch }}",
    ]
    assert [step["with"]["ref"] for step in build_checkouts] == ["${{ env.SOURCE_SHA }}"]
    assert '"$RUNNER_TEMP/pages-policy/check_pages_deployment.py"' in all_commands


def test_pages_promotion_guards_report_what_they_observed() -> None:
    """Every guard here runs under `bash -e`, and a bare `test` prints nothing when it fails,
    so the job's whole log becomes the runner's exit-code line. Pages run 34791052054 aborted
    on one of these, before the checker it gates was ever invoked, and said nothing."""

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    )
    expressions = []
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            lines = str(step.get("run", "")).splitlines()
            for index, line in enumerate(lines):
                guard = line.strip()
                if not guard.startswith("test "):
                    continue
                diagnostic, abort = (part.strip() for part in lines[index + 1 : index + 3])
                assert guard.endswith(" || {"), guard
                assert diagnostic.startswith('echo "[PAGES PROMOTION FAIL] '), guard
                assert diagnostic.endswith(">&2"), guard
                assert abort == "exit 1", guard
                expressions.append(guard[: -len(" || {")])

    assert sorted(set(expressions)) == [
        'test "$OPERATION" = "deploy-current"',
        'test "$ROLLBACK_CONFIRMATION" = "REDEPLOY_KNOWN_GOOD"',
        'test "$SOURCE_SHA" = "$DEFAULT_SHA"',
        'test -n "$CHECKS_RUN_ID"',
        'test -n "$KNOWN_GOOD_RECEIPT_RUN_ID"',
    ]
    assert len(expressions) == 8


def test_pages_deployment_credentials_never_execute_checked_out_code() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    )
    prepare = workflow["jobs"]["prepare"]
    build = workflow["jobs"]["build"]
    validate = workflow["jobs"]["validate"]
    deploy = workflow["jobs"]["deploy"]
    observe = workflow["jobs"]["observe"]

    assert prepare["permissions"] == {"actions": "read", "contents": "read"}
    assert build["permissions"] == {"contents": "read"}
    assert validate["permissions"] == {"actions": "read", "contents": "read"}
    assert deploy["permissions"] == {
        "contents": "read", "pages": "write", "id-token": "write",
    }
    assert observe["permissions"] == {"actions": "read", "contents": "read"}
    assert all("actions/checkout@" not in step.get("uses", "") for step in validate["steps"])
    assert all("actions/checkout@" not in step.get("uses", "") for step in deploy["steps"])
    deploy_commands = "\n".join(str(step.get("run", "")) for step in deploy["steps"])
    assert "python" not in deploy_commands
    assert "scripts/" not in deploy_commands
    assert [step.get("uses", "") for step in deploy["steps"] if step.get("uses")] == [
        "actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
    ]


def test_pages_rollback_is_explicitly_authorized_and_not_claimed_as_exercised() -> None:
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "Pages does not roll back automatically" in text
    assert "The guard is not authorization" in text
    assert "External rollback drill status: **NOT_CHECKED**" in text
    assert "No checklist, receipt, or confirmation string authorizes dispatch" in text


def test_contributor_surfaces_require_refresh_acceptance_and_aftercare() -> None:
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")

    assert "Mandatory pull-request promotion and aftercare" in agents
    assert "MUST NOT issue, fabricate" in agents
    assert "After an explicitly authorized merge" in contributing
    assert "without circular trust" in agents
    assert "one-time policy bootstrap" in contributing
    assert "require both the merge-queue-capable `conformance-gate`" in contributing
    assert "`ALLGREEN` grouping strategy" in contributing
    assert "more than 32 entries" in contributing
    assert "does not roll back deployed" in contributing
    for field in (
        "Final head commit",
        "Final base commit",
        "Executed integration commit",
        "Repository-check event",
        "Repository-check run",
        "Promotion record SHA-256",
        "Actionable findings",
        "Tests skipped or not run",
        "Human acceptance evidence",
        "Post-merge validation owner and surfaces",
    ):
        assert field in template
    assert "DISCLOSED — test-evidence-sha256=<64hex>" in template
    assert "NONE — test-evidence-sha256=<64hex>" in template
    assert "<64hex>` means exactly 64 lowercase hexadecimal characters" in template
    assert "## Test skip rubric disclosure" in template
    assert "OS_CAPABILITY_GUARD" in template
    assert "OPTIONAL_DEPENDENCY_ABSENT" in template
    assert "Mandatory test skip disclosure and rubric classification" in agents
    assert "docs/TEST_SKIP_RUBRIC.md" in agents
    assert "docs/TEST_SKIP_RUBRIC.md" in contributing


def test_the_description_is_rechecked_on_every_push_and_every_edit() -> None:
    """A push moves the tree and an edit moves the description; either can end agreement.

    The repository checks run the description gate on pushes only, so this workflow
    exists for the edit. It runs the pull request's own gate on the pull request's own
    tree, which is safe only without privileges, and it must never splice the
    description into a script.
    """
    text = (ROOT / ".github/workflows/pr-description.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow[True]  # the loader reads the bare key `on` as the boolean True
    assert set(triggers) == {"pull_request"}
    assert {"synchronize", "edited", "opened", "reopened"} <= set(triggers["pull_request"]["types"])
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"describes-head", "changed-since-last-push"}
    for job in workflow["jobs"].values():
        _assert_runs_the_pull_requests_own_tree_safely(job)

    job = workflow["jobs"]["describes-head"]
    assert "if" not in job
    (check,) = [step for step in job["steps"] if "check_pr_description.py" in str(step.get("run", ""))]
    assert check["env"]["DESCRIPTION"] == "${{ github.event.pull_request.body }}"
    assert check["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert '--commit "$HEAD_SHA"' in check["run"]


def _assert_runs_the_pull_requests_own_tree_safely(job: dict) -> None:
    checkout = next(step for step in job["steps"] if "actions/checkout@" in step.get("uses", ""))
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    assert all(level == "read" for level in job.get("permissions", {}).values()), job
    for step in job["steps"]:
        if "uses" in step:
            assert "@" in step["uses"] and len(step["uses"].split("@", 1)[1]) == 40, step["uses"]
        assert "${{" not in str(step.get("run", "")), step


def test_a_push_with_an_unrevised_description_fails_even_without_the_local_hook() -> None:
    """The pre-push gate stops such a push only where it is installed. This job is
    where a push that skipped it still fails. It judges the description as the push
    event carried it, against the one in force at the previous head's push, and no
    later edit may cancel that verdict.
    """
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/pr-description.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["changed-since-last-push"]
    assert job["if"] == "github.event.action == 'synchronize'"
    assert "concurrency" not in job and "concurrency" not in workflow
    assert job["permissions"] == {"contents": "read", "actions": "read", "pull-requests": "read"}
    (check,) = [step for step in job["steps"]
                if "check_pr_description_changed.py" in str(step.get("run", ""))]
    assert check["env"]["DESCRIPTION"] == "${{ github.event.pull_request.body }}"
    assert check["env"]["BEFORE"] == "${{ github.event.before }}"
    assert check["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert '--head "$BEFORE"' in check["run"]
    assert '--body "$RUNNER_TEMP/description.md"' in check["run"]
