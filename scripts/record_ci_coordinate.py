#!/usr/bin/env python3
"""Terminology: continuous integration (CI); identifier (ID).

Record distinct source and executed CI coordinates.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


FULL_COMMIT = re.compile(r"[0-9a-f]{40}")


def _commit(value: str, *, name: str, required: bool) -> str | None:
    if not value and not required:
        return None
    if FULL_COMMIT.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full lowercase commit identifier")
    return value


def coordinate(environment: dict[str, str]) -> dict[str, object]:
    event_name = environment.get("GITHUB_EVENT_NAME", "")
    executed = _commit(environment.get("GITHUB_SHA", ""), name="executed commit", required=True)
    pull_request = event_name == "pull_request"
    merge_group = event_name == "merge_group"
    run_id = environment.get("GITHUB_RUN_ID", "")
    run_attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    if re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        raise ValueError("run ID must be a positive integer")
    if re.fullmatch(r"[1-9][0-9]*", run_attempt) is None:
        raise ValueError("run attempt must be a positive integer")
    coordinate_kind = (
        "pull_request_integration"
        if pull_request
        else "merge_group_integration"
        if merge_group
        else "pushed_commit"
    )
    result: dict[str, object] = {
        "schema_version": 1,
        "event_name": event_name,
        "executed_coordinate_kind": coordinate_kind,
        "executed_commit": executed,
        "pull_request_head_commit": _commit(
            environment.get("PULL_REQUEST_HEAD_SHA", ""),
            name="pull-request head",
            required=pull_request,
        ),
        "pull_request_base_commit": _commit(
            environment.get("PULL_REQUEST_BASE_SHA", ""),
            name="pull-request base",
            required=pull_request,
        ),
        "merge_group_head_commit": _commit(
            environment.get("MERGE_GROUP_HEAD_SHA", ""),
            name="merge-group head",
            required=merge_group,
        ),
        "git_ref": environment.get("GITHUB_REF", ""),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "claim_boundary": (
            "These are workflow-platform and Git object observations; they do not establish "
            "correctness, human acceptance, merge identity, or publication."
        ),
    }
    if merge_group and result["merge_group_head_commit"] != executed:
        raise ValueError("merge-group head differs from the executed commit")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = coordinate(dict(os.environ))
    except ValueError as exc:
        print(f"[CI COORDINATE FAIL] {exc}")
        return 1
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print("[CI COORDINATE PASS] source and executed coordinates recorded distinctly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
