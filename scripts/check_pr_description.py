#!/usr/bin/env python3
"""Terminology: pull request (PR); JavaScript Object Notation (JSON).

Require the description's current head and check any claimed tracked-file count.
This is the existing public-family head contract: no mandatory source inventory,
domain catalogue, or new authoring schema. Protected default-branch code reads
GitHub's exact tree; it never imports or executes candidate source. Agreement is
not semantic verification, signature verification, acceptance, or authorization.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

HEAD_LINE = re.compile(r"Current (?:signed )?head:\s*`?([0-9a-f]{40})`?")
INVENTORY = re.compile(r"tracked inventory is ([\d,]+) files")
TRACKED_TYPES = frozenset({"blob", "commit"})


class Unanswered(ValueError):
    """The platform did not establish the requested exact tree coordinate."""


def tracked_files(repository: str, commit: str) -> int:
    try:
        result = subprocess.run(["gh", "api", f"repos/{repository}/git/trees/{commit}?recursive=1"],
                                capture_output=True, timeout=30)
        if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
            raise Unanswered("tree query failed or exceeded its response bound")
        tree = json.loads(result.stdout)
        if tree.get("truncated") is not False or type(tree.get("tree")) is not list:
            raise Unanswered("complete tree unavailable")
        return sum(1 for entry in tree["tree"] if entry.get("type") in TRACKED_TYPES)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError) as error:
        raise Unanswered("exact complete tree unavailable") from error


def findings(body: str, head: str, repository: str) -> list[str]:
    found = []
    named = HEAD_LINE.findall(body)
    if not named or any(value != head for value in named):
        found.append("name the exact current head using Current head: followed by its full identifier")
    stated = INVENTORY.findall(body)
    if stated:
        actual = tracked_files(repository, head)
        if any(int(value.replace(",", "")) != actual for value in stated):
            found.append("the claimed tracked-file inventory differs from the exact head")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--body", type=Path)
    source.add_argument("--event", type=Path)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or not re.fullmatch(r"[0-9a-f]{40}", args.commit):
            raise Unanswered("invalid repository or commit coordinate")
        path = args.event if args.event is not None else args.body
        if path.stat().st_size > 1024 * 1024:
            raise Unanswered("description byte bound exceeded")
        text = path.read_text(encoding="utf-8")
        if args.event is not None:
            event = json.loads(text)
            if event["repository"]["full_name"] != args.repo or event["pull_request"]["head"]["sha"] != args.commit:
                raise Unanswered("event coordinate differs")
            text = event["pull_request"].get("body") or ""
            if type(text) is not str:
                raise Unanswered("event description is not text")
        result = findings(text, args.commit, args.repo)
    except (Unanswered, OSError, UnicodeError, ValueError, KeyError, TypeError):
        print("[PR DESCRIPTION HEAD] UNKNOWN: exact bounded input or tree unavailable")
        return 1
    print(json.dumps({"status": "FAIL" if result else "PASS", "findings": result}))
    return int(bool(result))


if __name__ == "__main__":
    raise SystemExit(main())
