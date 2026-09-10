"""Adversarial tests for notification-only lifecycle wakeups."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEAD, BASE = "a" * 40, "b" * 40
REPOSITORY = "example/project"


def _module():
    spec = importlib.util.spec_from_file_location("policy_notification", ROOT / "scripts/check_policy_notification.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _records(kind: str = "pull_request_review") -> tuple[dict, dict]:
    module = _module()
    return (
        {"id": 17, "workflow_id": 19, "name": module.WORKFLOW_NAME, "path": module.WORKFLOW_PATH,
         "repository": {"full_name": REPOSITORY}, "head_sha": HEAD, "event": kind,
         "head_branch": f"gh-readonly-queue/main/pr-31-{BASE}",
         "pull_requests": [{"number": 31, "head": {"sha": HEAD}}], "conclusion": "failure"},
        {"id": 19, "name": module.WORKFLOW_NAME, "path": module.WORKFLOW_PATH},
    )


def _resolve(module, run: dict, workflow: dict) -> dict:
    return module.resolve_notification(run, workflow, repository=REPOSITORY, run_id="17")


@pytest.mark.parametrize("conclusion", (None, "success", "failure", "cancelled", "timed_out"))
def test_notification_conclusion_is_not_acceptance_or_a_delivery_filter(conclusion: str | None) -> None:
    module = _module()
    run, workflow = _records()
    run["conclusion"] = conclusion
    result = _resolve(module, run, workflow)
    assert result == {"kind": "pull_request_review", "head_sha": HEAD, "run_id": "17", "pull_request_number": 31}
    assert "result" not in result


@pytest.mark.parametrize("field,value", (
    ("id", True), ("id", 18), ("workflow_id", 20), ("name", "namesake"),
    ("path", ".github/workflows/namesake.yml"), ("repository", {"full_name": "other/project"}),
    ("head_sha", "short"), ("event", "push"), ("event", "workflow_dispatch"),
    ("pull_requests", []), ("pull_requests", [{"number": True, "head": {"sha": HEAD}}]),
    ("pull_requests", [{"number": 31, "head": {"sha": BASE}}]),
    ("pull_requests", [{"number": 31, "head": {"sha": HEAD}}, {"number": 32, "head": {"sha": HEAD}}]),
))
def test_notification_rejects_substituted_or_ambiguous_run(field: str, value: object) -> None:
    module = _module()
    run, workflow = _records()
    run[field] = value
    with pytest.raises(module.PolicyNotificationError):
        _resolve(module, run, workflow)


@pytest.mark.parametrize("field,value", (("path", ".github/workflows/namesake.yml"), ("name", "other"), ("id", 20)))
def test_notification_binds_fresh_workflow_metadata(field: str, value: object) -> None:
    module = _module()
    run, workflow = _records()
    workflow[field] = value
    with pytest.raises(module.PolicyNotificationError):
        _resolve(module, run, workflow)


@pytest.mark.parametrize("mutation", (None, "head", "number", "repository", "closed"))
def test_review_wakeup_requires_current_exact_open_pull_request(mutation: str | None) -> None:
    module = _module()
    target = _resolve(module, *_records())
    pr = {"number": 31, "state": "open", "head": {"sha": HEAD}, "base": {"repo": {"full_name": REPOSITORY}}}
    if mutation == "head": pr["head"]["sha"] = BASE
    elif mutation == "number": pr["number"] = 32
    elif mutation == "repository": pr["base"]["repo"]["full_name"] = "other/project"
    elif mutation == "closed": pr["state"] = "closed"
    if mutation is None:
        module.confirm_review(target, pr, repository=REPOSITORY)
    else:
        with pytest.raises(module.PolicyNotificationError):
            module.confirm_review(target, pr, repository=REPOSITORY)


@pytest.mark.parametrize("mutation", (None, "moved-ref", "wrong-ref", "tag", "wrong-commit", "wrong-parent", "no-parent", "many-parents"))
def test_queue_event_requires_authenticated_ref_and_unambiguous_commit_parent(mutation: str | None) -> None:
    module = _module()
    target = _resolve(module, *_records("merge_group"))
    commit = {"sha": HEAD, "parents": [{"sha": BASE}, {"sha": "c" * 40}]}
    ref = {"ref": target["head_ref"], "object": {"type": "commit", "sha": HEAD}}
    if mutation == "moved-ref": ref["object"]["sha"] = BASE
    elif mutation == "wrong-ref": ref["ref"] = "refs/heads/main"
    elif mutation == "tag": ref["object"]["type"] = "tag"
    elif mutation == "wrong-commit": commit["sha"] = BASE
    elif mutation == "wrong-parent": commit["parents"][0]["sha"] = HEAD
    elif mutation == "no-parent": commit["parents"] = []
    elif mutation == "many-parents": commit["parents"] *= 2
    if mutation is None:
        result = module.merge_group_event(target, commit, ref)
        assert result == {"action": "checks_requested", "merge_group": {"head_sha": HEAD, "head_ref": target["head_ref"], "base_sha": BASE, "base_ref": "refs/heads/main"}}
    else:
        with pytest.raises(module.PolicyNotificationError):
            module.merge_group_event(target, commit, ref)


@pytest.mark.parametrize("branch", ("main", "gh-readonly-queue/main/pr-31-short", f"gh-readonly-queue/../main/pr-31-{BASE}", "x" * 513))
def test_queue_wakeup_ref_must_have_the_supported_bounded_shape(branch: str) -> None:
    module = _module()
    run, workflow = _records("merge_group")
    run["head_branch"] = branch
    with pytest.raises(module.PolicyNotificationError):
        _resolve(module, run, workflow)
