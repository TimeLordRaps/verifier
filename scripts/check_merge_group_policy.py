#!/usr/bin/env python3
"""Validate bounded merge-queue membership and exact pull-request receipts.

Terminology: JavaScript Object Notation (JSON); pull request (PR);
Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

The merge-group event does not directly enumerate its pull requests. This check
conservatively requires current policy receipts for the terminal pull request and
every earlier entry returned by the bounded merge-queue query. That set can be a
superset of one GitHub merge group, but it cannot omit an earlier constituent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
QUEUE_REF = re.compile(
    r"^refs/heads/gh-readonly-queue/(?P<branch>.+)/pr-(?P<number>[1-9][0-9]*)-"
    r"(?P<base>[0-9a-f]{40})$"
)
MAX_QUEUE_ENTRIES = 32
MAX_JSON_BYTES = 4 * 1024 * 1024


class MergeGroupPolicyError(ValueError):
    """Raised when merge-group membership or receipts are incomplete."""


def _load(path: Path) -> Any:
    with path.open("rb") as stream:
        payload = stream.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise MergeGroupPolicyError("merge-group evidence exceeds the JSON byte limit")
    return json.loads(payload.decode("utf-8"))


def _coordinates(event: dict[str, Any]) -> tuple[str, str, str, int]:
    if event.get("action") != "checks_requested":
        raise MergeGroupPolicyError("merge-group action must be checks_requested")
    group = event.get("merge_group")
    if not isinstance(group, dict):
        raise MergeGroupPolicyError("event has no merge_group object")
    head = group.get("head_sha")
    base = group.get("base_sha")
    head_ref = group.get("head_ref")
    base_ref = group.get("base_ref")
    if not all(isinstance(value, str) for value in (head, base, head_ref, base_ref)):
        raise MergeGroupPolicyError("merge-group coordinates are unavailable")
    if FULL_COMMIT.fullmatch(head) is None or FULL_COMMIT.fullmatch(base) is None:
        raise MergeGroupPolicyError("merge-group commits must be full lowercase identifiers")
    match = QUEUE_REF.fullmatch(head_ref)
    if match is None:
        raise MergeGroupPolicyError("merge-group head ref has an unrecognized bounded form")
    if base_ref != f"refs/heads/{match.group('branch')}" or base != match.group("base"):
        raise MergeGroupPolicyError("merge-group ref does not bind its base branch and commit")
    return head, base, head_ref, int(match.group("number"))


def _entries(queue: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        connection = queue["data"]["repository"]["pullRequest"]["mergeQueue"]["entries"]
        nodes = connection["nodes"]
        has_next = connection["pageInfo"]["hasNextPage"]
        total = connection["totalCount"]
    except (KeyError, TypeError) as exc:
        raise MergeGroupPolicyError("merge-queue query has an incomplete shape") from exc
    if has_next or not isinstance(total, int) or total > MAX_QUEUE_ENTRIES:
        raise MergeGroupPolicyError("merge queue exceeds the bounded entry limit")
    if not isinstance(nodes, list) or len(nodes) != total or not nodes:
        raise MergeGroupPolicyError("merge-queue query did not return every declared entry")
    return nodes


def build_manifest(event: dict[str, Any], queue: dict[str, Any]) -> dict[str, Any]:
    head, base, head_ref, terminal_number = _coordinates(event)
    nodes = _entries(queue)
    normalized: list[tuple[int, int]] = []
    for node in nodes:
        if not isinstance(node, dict):
            raise MergeGroupPolicyError("merge-queue entry is not an object")
        position = node.get("position")
        pull_request = node.get("pullRequest")
        number = pull_request.get("number") if isinstance(pull_request, dict) else None
        if (
            not isinstance(position, int)
            or position < 1
            or not isinstance(number, int)
            or number < 1
        ):
            raise MergeGroupPolicyError("merge-queue entry lacks a positive position or PR number")
        normalized.append((position, number))
    if len({position for position, _ in normalized}) != len(normalized):
        raise MergeGroupPolicyError("merge-queue positions are not unique")
    terminal = next((position for position, number in normalized if number == terminal_number), None)
    if terminal is None:
        raise MergeGroupPolicyError("terminal PR is absent from the current merge queue")
    selected = [(position, number) for position, number in sorted(normalized) if position <= terminal]
    members = [number for _, number in selected]
    if len(members) != len(set(members)):
        raise MergeGroupPolicyError("merge-queue PR numbers are not unique")
    return {
        "schema_version": 1,
        "result": "PENDING_RECEIPTS",
        "merge_group_head_sha": head,
        "merge_group_base_sha": base,
        "merge_group_head_ref": head_ref,
        "terminal_pull_request": terminal_number,
        "required_pull_requests": members,
        "queue_observation_sha256": hashlib.sha256(
            json.dumps(selected, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def confirm(
    *,
    manifest: dict[str, Any],
    current_event: dict[str, Any],
    current_queue: dict[str, Any],
    receipts_dir: Path,
) -> dict[str, Any]:
    current = build_manifest(current_event, current_queue)
    for field in (
        "merge_group_head_sha",
        "merge_group_base_sha",
        "merge_group_head_ref",
        "terminal_pull_request",
        "required_pull_requests",
        "queue_observation_sha256",
    ):
        if current.get(field) != manifest.get(field):
            raise MergeGroupPolicyError(f"merge-group {field} changed during evaluation")
    numbers = manifest.get("required_pull_requests")
    if not isinstance(numbers, list) or not numbers:
        raise MergeGroupPolicyError("manifest has no required pull requests")
    observed: list[dict[str, Any]] = []
    for number in numbers:
        receipt_path = receipts_dir / f"{number}.json"
        if not receipt_path.is_file():
            raise MergeGroupPolicyError(f"missing exact policy receipt for PR {number}")
        receipt = _load(receipt_path)
        if receipt.get("result") != "PASS" or receipt.get("pull_request_number") != number:
            raise MergeGroupPolicyError(f"invalid exact policy receipt for PR {number}")
        observed.append(
            {
                "pull_request_number": number,
                "head_sha": receipt.get("head_sha"),
                "base_sha": receipt.get("base_sha"),
                "promotion_record_sha256": receipt.get("promotion_record_sha256"),
                "pull_request_body_sha256": receipt.get("pull_request_body_sha256"),
            }
        )
    result = dict(manifest)
    result["result"] = "PASS"
    result["constituent_receipts"] = observed
    result["claim_boundary"] = (
        "Every bounded earlier-or-terminal merge-queue entry had a current exact policy "
        "receipt at evaluation time; future queue, pull-request, or credential state is not established."
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirm-current", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--receipts-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        event = _load(args.event)
        queue = _load(args.queue)
        if args.confirm_current:
            if args.manifest is None or args.receipts_dir is None:
                raise MergeGroupPolicyError("confirmation requires manifest and receipt directory")
            result = confirm(
                manifest=_load(args.manifest),
                current_event=event,
                current_queue=queue,
                receipts_dir=args.receipts_dir,
            )
        else:
            result = build_manifest(event, queue)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
    except (OSError, UnicodeError, json.JSONDecodeError, MergeGroupPolicyError) as exc:
        print(f"[MERGE GROUP POLICY FAIL] {exc}")
        return 1
    print(f"[MERGE GROUP POLICY {result['result']}] {len(result['required_pull_requests'])} PR(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
