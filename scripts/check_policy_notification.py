#!/usr/bin/env python3
"""Resolve an untrusted notification through freshly fetched platform metadata.

Terminology: application programming interface (API); JavaScript Object Notation
(JSON); pull request (PR); Verifier Standard (VSTD).

Notification code, artifacts, and conclusions are not evidence of acceptance.
The protected consumer supplies authenticated GitHub API responses. Missing or
ambiguous associations fail closed; this resolver cannot guarantee event delivery.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any


WORKFLOW_PATH = ".github/workflows/pr-policy-notification.yml"
WORKFLOW_NAME = "pull-request-policy-notification"
COMMIT = re.compile(r"[0-9a-f]{40}")
QUEUE = re.compile(r"gh-readonly-queue/(?P<branch>[A-Za-z0-9._/-]+)/pr-(?P<number>[1-9][0-9]*)-(?P<base>[0-9a-f]{40})")
MAX_JSON_BYTES = 4 * 1024 * 1024


class PolicyNotificationError(ValueError):
    """The wakeup cannot be bound to exact current platform coordinates."""


def _require(condition: bool) -> None:
    if not condition:
        raise PolicyNotificationError("notification identity or current coordinate is invalid")


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _commit(value: Any) -> bool:
    return isinstance(value, str) and COMMIT.fullmatch(value) is not None


def resolve_notification(
    run: dict[str, Any], workflow: dict[str, Any], *, repository: str, run_id: str,
) -> dict[str, Any]:
    """Use a run only as a wakeup, including failed or cancelled runs."""
    _require(isinstance(run, dict) and isinstance(workflow, dict))
    _require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None)
    _require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None)
    _require(_positive(run.get("id")) and str(run["id"]) == run_id)
    _require(run.get("name") == WORKFLOW_NAME and run.get("path") == WORKFLOW_PATH)
    _require(_positive(run.get("workflow_id")) and run["workflow_id"] == workflow.get("id"))
    _require(workflow.get("path") == WORKFLOW_PATH and workflow.get("name") == WORKFLOW_NAME)
    repo = run.get("repository")
    _require(isinstance(repo, dict) and repo.get("full_name") == repository)
    _require(_commit(run.get("head_sha")))
    kind = run.get("event")
    _require(kind in {"pull_request_review", "merge_group"})
    result: dict[str, Any] = {"kind": kind, "head_sha": run["head_sha"], "run_id": run_id}
    if kind == "pull_request_review":
        prs = run.get("pull_requests")
        _require(isinstance(prs, list) and len(prs) == 1 and isinstance(prs[0], dict))
        number = prs[0].get("number")
        head = prs[0].get("head")
        _require(_positive(number) and isinstance(head, dict) and head.get("sha") == run["head_sha"])
        result["pull_request_number"] = number
    else:
        branch = run.get("head_branch")
        _require(isinstance(branch, str) and len(branch) <= 512)
        match = QUEUE.fullmatch(branch)
        _require(match is not None)
        assert match is not None
        _require(all(part not in {"", ".", ".."} for part in match.group("branch").split("/")))
        result.update(head_ref=f"refs/heads/{branch}", base_ref=f"refs/heads/{match.group('branch')}", base_sha=match.group("base"))
    return result


def confirm_review(target: dict[str, Any], pull_request: dict[str, Any], *, repository: str) -> None:
    _require(target.get("kind") == "pull_request_review" and isinstance(pull_request, dict))
    head, base = pull_request.get("head"), pull_request.get("base")
    _require(isinstance(head, dict) and isinstance(base, dict))
    repo = base.get("repo")
    _require(isinstance(repo, dict) and repo.get("full_name") == repository)
    _require(pull_request.get("state") == "open" and pull_request.get("number") == target.get("pull_request_number"))
    _require(head.get("sha") == target.get("head_sha"))


def merge_group_event(target: dict[str, Any], commit: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    """Recover only the queue shape whose ref and first parent bind one exact base."""
    _require(target.get("kind") == "merge_group" and isinstance(commit, dict) and isinstance(ref, dict))
    _require(commit.get("sha") == target.get("head_sha") and ref.get("ref") == target.get("head_ref"))
    obj, parents = ref.get("object"), commit.get("parents")
    _require(isinstance(obj, dict) and obj.get("type") == "commit" and obj.get("sha") == target.get("head_sha"))
    _require(isinstance(parents, list) and 1 <= len(parents) <= 2)
    _require(all(isinstance(parent, dict) and _commit(parent.get("sha")) for parent in parents))
    _require(parents[0]["sha"] == target.get("base_sha"))
    return {"action": "checks_requested", "merge_group": {key: target[key] for key in ("head_sha", "head_ref", "base_sha", "base_ref")}}


def _load(path: Path) -> Any:
    with path.open("rb") as stream:
        payload = stream.read(MAX_JSON_BYTES + 1)
    _require(len(payload) <= MAX_JSON_BYTES)
    return json.loads(payload.decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--current-pr", type=Path)
    parser.add_argument("--merge-commit", type=Path)
    parser.add_argument("--merge-ref", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = resolve_notification(_load(args.run), _load(args.workflow), repository=args.repository, run_id=args.run_id)
        if args.current_pr is not None:
            confirm_review(result, _load(args.current_pr), repository=args.repository)
        if args.merge_commit is not None or args.merge_ref is not None:
            _require(args.merge_commit is not None and args.merge_ref is not None)
            result = merge_group_event(result, _load(args.merge_commit), _load(args.merge_ref))
        args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        print(f"[POLICY NOTIFICATION FAIL] {type(exc).__name__}")
        return 1
    print("[POLICY NOTIFICATION RESOLVED] wakeup only; current policy evaluation remains required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
