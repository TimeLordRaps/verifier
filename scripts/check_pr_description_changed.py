#!/usr/bin/env python3
"""Terminology: JavaScript Object Notation (JSON); pull request (PR).

Refuse a push that leaves a pull-request description word for word unchanged.

A description is written for the head it describes, so every push of a new head has
to come with a revised description. This check compares the description with the one
that was in force when the pull request's current head was pushed. If the two are
the same word for word, the push is refused. Only words are compared: an edit that
changes nothing but spacing or line endings is not a revision.

Nothing is stored. GitHub keeps every revision of a description with the moment it
was made, and the first pull-request workflow run on a head marks the moment that
head was pushed. Later runs on the same head come from edits, so the first is the
push. The revision in force at that moment is the reference.

A revised description is not thereby a correct one. `check_pr_description.py` checks
what the description says against the tree; this check establishes only that the
description was revised since the last push.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys

PULL_REQUEST_EVENTS = frozenset({"pull_request", "pull_request_target"})
REVISIONS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      userContentEdits(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { editedAt deletedAt diff }
      }
    }
  }
}
"""


class Unanswered(Exception):
    """A question GitHub did not answer. It is not a no."""


def words(text: str) -> list[str]:
    return text.split()


def _instant(moment: str) -> datetime:
    return datetime.fromisoformat(moment.replace("Z", "+00:00"))


def pushed_at(runs: list[dict], number: int) -> str | None:
    """The moment a head was pushed to pull request `number`: its first run there."""

    moments = [
        run["created_at"] for run in runs
        if run.get("event") in PULL_REQUEST_EVENTS
        and (not run.get("pull_requests") or number in run["pull_requests"])
    ]
    return min(moments, key=_instant) if moments else None


def in_force(revisions: list[dict], moment: str) -> dict | None:
    """The revision in force at `moment`: the latest one made at or before it."""

    earlier = [revision for revision in revisions
               if _instant(revision["editedAt"]) <= _instant(moment)]
    return max(earlier, key=lambda revision: _instant(revision["editedAt"])) if earlier else None


def _gh(arguments: list[str]) -> str:
    try:
        result = subprocess.run(["gh", *arguments], capture_output=True, text=True,
                                encoding="utf-8", timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise Unanswered(f"gh could not be run: {error}") from error
    if result.returncode != 0:
        raise Unanswered(f"gh {' '.join(arguments[:2])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def fetch_pull(repository: str, number: int) -> tuple[str, str]:
    """The live description and the current head of a pull request."""

    data = json.loads(_gh(["pr", "view", str(number), "--repo", repository,
                           "--json", "body,headRefOid"]))
    return data.get("body") or "", data["headRefOid"]


def fetch_runs(repository: str, head: str) -> list[dict]:
    output = _gh([
        "api", "--paginate", f"repos/{repository}/actions/runs?head_sha={head}&per_page=100",
        "--jq", ".workflow_runs[] | {created_at, event, "
                "pull_requests: [.pull_requests[].number]} | @json",
    ])
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def fetch_revisions(repository: str, number: int) -> list[dict]:
    owner, name = repository.split("/", 1)
    revisions: list[dict] = []
    cursor: str | None = None
    while True:
        arguments = ["api", "graphql", "-f", f"query={REVISIONS_QUERY}", "-f", f"owner={owner}",
                     "-f", f"name={name}", "-F", f"number={number}"]
        if cursor:
            arguments += ["-f", f"cursor={cursor}"]
        page = json.loads(_gh(arguments))["data"]["repository"]["pullRequest"]["userContentEdits"]
        revisions.extend(page["nodes"])
        if not page["pageInfo"]["hasNextPage"]:
            return revisions
        cursor = page["pageInfo"]["endCursor"]


def check(repository: str, number: int, head: str | None = None,
          body: str | None = None) -> tuple[bool, str]:
    """Return (revised, message) for pull request `number`.

    `head` is the head whose push fixes the reference; by default the pull request's
    current head, the one a push is about to replace. `body` is the description being
    judged; by default the live one.
    """

    if head is None or body is None:
        live_body, current_head = fetch_pull(repository, number)
        head = current_head if head is None else head
        body = live_body if body is None else body
    moment = pushed_at(fetch_runs(repository, head), number)
    if moment is None:
        raise Unanswered(
            f"no pull-request workflow run on {head[:12]} records when it was pushed, so the "
            "description in force then cannot be found. If it was pushed a moment ago, wait "
            "for its first run and try again."
        )
    revisions = fetch_revisions(repository, number)
    if not revisions:
        # Never edited: every copy of the description is the one it was opened with.
        return False, (f"pull request #{number}'s description has never been edited, so it is "
                       f"word for word the one in force when {head[:12]} was pushed ({moment}).")
    reference = in_force(revisions, moment)
    if reference is None:
        raise Unanswered(f"no revision of pull request #{number}'s description is as old as the "
                         f"push of {head[:12]} ({moment}).")
    if reference.get("deletedAt") or reference.get("diff") is None:
        raise Unanswered(f"the revision of pull request #{number}'s description in force when "
                         f"{head[:12]} was pushed has been deleted from its history.")
    if words(body) == words(reference["diff"]):
        return False, (f"pull request #{number}'s description is word for word the one in force "
                       f"when {head[:12]} was pushed ({moment}; revision of "
                       f"{reference['editedAt']}).")
    return True, (f"pull request #{number}'s description has been revised since {head[:12]} "
                  f"was pushed ({moment}).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="OWNER/NAME holding the pull request")
    parser.add_argument("--pr", required=True, type=int, help="pull request number")
    parser.add_argument("--head", help="the head whose push fixes the reference; defaults to "
                                       "the pull request's current head")
    parser.add_argument("--body", type=Path, help="judge the description in this file; "
                                                  "defaults to the live description")
    args = parser.parse_args(argv)

    body = None if args.body is None else args.body.read_text(encoding="utf-8")
    try:
        revised, message = check(args.repo, args.pr, args.head, body)
    except (Unanswered, KeyError, TypeError, ValueError) as error:
        print(f"[PR DESCRIPTION CHANGE] FAIL: {error}")
        return 1
    if revised:
        print(f"[PR DESCRIPTION CHANGE] PASS: {message}")
        return 0
    print(f"[PR DESCRIPTION CHANGE] FAIL: {message}")
    print("  Revise the description for what this push adds, then push again.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
