#!/usr/bin/env python3
"""Terminology: Boolean satisfiability problem (SAT); command-line interface (CLI);
conjunctive normal form (CNF); continuous integration (CI); Extensible Markup Language
(XML); Hypertext Transfer Protocol (HTTP); identifier (ID); JavaScript Object Notation
(JSON); operating system (OS); pull request (PR); Secure Hash Algorithm 256-bit
(SHA-256); uniform resource locator (URL); Verifier Standard (VSTD).

Check that a pull-request description still describes the branch it is attached to.

`check_pr_policy.py` checks that the promotion record is complete and accepted.
This check is the separate question of whether the description's technical inventory
is still true: whether it names the domains that exist, counts the checks that exist,
binds the head that exists, inventories the files that exist, and keeps the
fields another workflow parses machine-readable.

A description is evidence a reviewer reads instead of the tree. A description that
silently stopped matching the tree is a claim without evidence, so every mismatch
here is a failure rather than a warning. This check establishes agreement between a
description and a working tree. It does not establish that either one is correct,
that the described work was reviewed, or that a human understood it.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]

# Where tree facts are read from: the working tree, unless `use_commit` repoints
# them at a commit's own tree.
SOURCE = ROOT / "src"
COMMIT: str | None = None
TREE = "working tree"

# The description states counts in words, as prose does.
NUMBER_WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
    8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
    14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
    19: "nineteen", 20: "twenty",
}

# Adapter support modules carry no domain of their own.
NON_DOMAIN_MODULES = frozenset({
    "__init__", "catalog", "certification", "common", "numerical",
    "statics", "mainstays",
})

# Either dash spelling is accepted; the description uses an en dash.
DASH = r"[–—-]"


def _fail(findings: list[str], message: str) -> None:
    findings.append(message)


def domain_inventory() -> dict[str, int]:
    """Read the executable domain catalogue as the source of truth."""
    sys.path.insert(0, str(SOURCE))
    from verifier.domains.catalog import CHECKS  # noqa: PLC0415

    return {domain: len(checks) for domain, checks in CHECKS.items()}


def adapter_modules() -> set[str]:
    """Name every adapter module that is not shared support code."""
    directory = SOURCE / "verifier" / "domains"
    return {
        path.stem.upper()
        for path in sorted(directory.glob("*.py"))
        if path.stem not in NON_DOMAIN_MODULES
    }


def tracked_file_count() -> int:
    command = ["git", "ls-tree", "-r", "--name-only", COMMIT] if COMMIT else ["git", "ls-files"]
    result = subprocess.run(
        command, cwd=str(ROOT), capture_output=True, text=True, timeout=120,
    )
    result.check_returncode()
    return len([line for line in result.stdout.splitlines() if line.strip()])


def use_commit(commit: str, into: Path) -> str:
    """Read every tree fact from `commit` instead of the working tree.

    A push publishes a commit, not a working tree. The checkout may sit at another
    commit, or carry changes the pushed commit does not, and either would let a
    stale description pass. So the commit's `src` is extracted from the object
    database into `into` and its catalogue is the one imported, the inventory is
    its tree's, and the head is the commit itself.
    """
    global SOURCE, COMMIT, TREE
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    resolved.check_returncode()
    oid = resolved.stdout.strip()
    archive = subprocess.run(
        ["git", "archive", "--format=tar", oid, "src"],
        cwd=str(ROOT), capture_output=True, timeout=120,
    )
    archive.check_returncode()
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as bundle:
        # The data filter is absent before 3.10.12; the archive is our own object
        # database, not an untrusted download, so its absence is not a hazard.
        if hasattr(tarfile, "data_filter"):
            bundle.extractall(into, filter="data")
        else:  # pragma: no cover
            bundle.extractall(into)
    SOURCE, COMMIT, TREE = into / "src", oid, f"commit {oid[:12]}"
    return oid


def head_commit() -> str:
    if COMMIT:
        return COMMIT
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    result.check_returncode()
    return result.stdout.strip()


def check_domains_are_described(body: str, findings: list[str]) -> None:
    """Every executable domain appears with its exact coordinate range, and no other."""
    inventory = domain_inventory()
    modules = adapter_modules()

    missing_modules = modules - set(inventory)
    if missing_modules:
        _fail(findings, (
            "adapter modules exist that the catalogue does not declare: "
            f"{', '.join(sorted(missing_modules))}. Add them to CHECKS in "
            "src/verifier/domains/catalog.py, then describe them."
        ))
    absent_modules = set(inventory) - modules
    if absent_modules:
        _fail(findings, (
            "the catalogue declares domains with no adapter module: "
            f"{', '.join(sorted(absent_modules))}."
        ))

    for domain, count in sorted(inventory.items()):
        if not re.search(rf"\b{domain}\b", body):
            _fail(findings, (
                f"domain {domain} is executable but the description never names it."
            ))
            continue
        span = rf"{domain}\.1\s*{DASH}\s*(?:{domain}\.)?{count}\b"
        if not re.search(span, body):
            _fail(findings, (
                f"the description does not state {domain}'s coordinate range as "
                f"{domain}.1-{domain}.{count}; the catalogue declares {count} checks."
            ))

    described = set(re.findall(r"\b([A-Z][A-Z0-9]{2,})\.\d+\b", body))
    unknown = {name for name in described if name not in inventory and name.startswith("VSTD") is False}
    unknown -= {"SHA", "JSON", "CNF", "SAT", "HTTP", "PDF", "CI", "OS", "PR", "URL", "ID", "XML"}
    for name in sorted(unknown):
        _fail(findings, (
            f"the description states {name} check coordinates, but the catalogue "
            f"declares no {name} domain."
        ))


def check_counts_are_described(body: str, findings: list[str]) -> None:
    """The stated domain and check totals equal the executable totals."""
    inventory = domain_inventory()
    domains = len(inventory)
    checks = sum(inventory.values())

    domain_word = NUMBER_WORDS.get(domains, str(domains))
    if not re.search(rf"\b(?:{domain_word}|{domains})\b[^.\n]{{0,60}}domain adapters", body, re.IGNORECASE):
        _fail(findings, (
            f"the description does not state that there are {domain_word} ({domains}) "
            "domain adapters."
        ))

    if not re.search(rf"\b{checks}\b[^.\n]{{0,40}}(?:computational |domain |native )?checks", body, re.IGNORECASE):
        _fail(findings, (
            f"the description does not state the total of {checks} domain checks "
            f"({' + '.join(str(inventory[d]) for d in sorted(inventory))})."
        ))


def check_head_is_bound(body: str, findings: list[str], head: str | None = None) -> None:
    """The described signed head equals the actual head.

    A caller supplies `head` where the checked-out commit is not the head under
    review, as on a pull-request merge ref; otherwise it is read from the tree.
    """
    head = head or head_commit()
    stated = re.findall(r"Current signed head:\s*`?([0-9a-f]{40})`?", body)
    if not stated:
        _fail(findings, "the description states no `Current signed head:` commit.")
        return
    for value in stated:
        if value != head:
            _fail(findings, (
                f"the description binds head {value[:12]}, but the head being checked is "
                f"{head[:12]}. Refresh the evidence and the promotion record; a "
                "validation record does not carry forward to a new head."
            ))


def check_inventory_is_bound(body: str, findings: list[str]) -> None:
    """The described tracked-file inventory equals the actual inventory."""
    stated = re.findall(r"tracked inventory is ([\d,]+) files", body)
    if not stated:
        _fail(findings, "the description states no tracked file inventory.")
        return
    actual = tracked_file_count()
    for value in stated:
        if int(value.replace(",", "")) != actual:
            _fail(findings, (
                f"the description states a tracked inventory of {value} files; the "
                f"{TREE} tracks {actual}."
            ))


def check_machine_read_fields_are_parseable(body: str, findings: list[str]) -> None:
    """Fields the promotion-check workflow parses must stay machine-readable.

    `pr-policy.yml` extracts the repository-check run with an anchored
    digits-only expression. Prose appended to that line does not degrade the
    workflow gracefully: the extraction yields nothing, the step exits on an
    empty value, and the failure surfaces with no explanation of its cause.
    This check reproduces the workflow's own expression so the mismatch is
    reported here, with the reason, before a push.
    """
    if "Repository-check run:" not in body:
        _fail(findings, "the promotion record states no `Repository-check run:` field.")
        return
    if not re.search(r"^- Repository-check run:\s*([1-9][0-9]*)\s*$", body, re.MULTILINE):
        _fail(findings, (
            "the `- Repository-check run:` line is not parseable by pr-policy.yml, "
            "which reads it as digits alone on the line. Qualifying prose belongs on "
            "a following line, not appended to this one."
        ))


def resolve_body(args: argparse.Namespace) -> str | None:
    """Read the description from a file, or from the pull request for this branch."""
    if args.body is not None:
        return args.body.read_text(encoding="utf-8")

    command = ["gh", "pr", "view", "--json", "body", "--jq", ".body"]
    if args.repo:
        command[3:3] = ["--repo", args.repo]
    if args.pr:
        command.insert(3, str(args.pr))
    try:
        result = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[PR DESCRIPTION] UNKNOWN: could not run gh ({error}).")
        return None
    if result.returncode != 0:
        detail = result.stderr.strip()
        if "no pull requests found" in detail.lower() or "no default remote" in detail.lower():
            print("[PR DESCRIPTION] PASS: no pull request is attached to this branch.")
            return None
        print(f"[PR DESCRIPTION] UNKNOWN: gh could not read the description: {detail}")
        return None
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, help="read the description from this file")
    parser.add_argument("--pr", help="pull request number; defaults to the current branch")
    parser.add_argument("--repo", help="OWNER/NAME holding the pull request; defaults to gh's choice")
    bound = parser.add_mutually_exclusive_group()
    bound.add_argument(
        "--head",
        help="commit the description must bind; defaults to the checked-out head. "
             "Supply the pull-request head when running on a merge ref.",
    )
    bound.add_argument(
        "--commit",
        help="check against this commit's own tree instead of the working tree: its "
             "catalogue, its inventory, and itself as the head. Used before a push.",
    )
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--require-pull-request",
        action="store_true",
        help="fail when no description can be read, instead of passing",
    )
    args = parser.parse_args(argv)

    body = resolve_body(args)
    if body is None:
        return 1 if args.require_pull_request else 0

    with tempfile.TemporaryDirectory(prefix="vstd-pr-description-",
                                     ignore_cleanup_errors=True) as scratch:
        if args.commit:
            sys.dont_write_bytecode = True
            try:
                use_commit(args.commit, Path(scratch))
            except (OSError, subprocess.SubprocessError, tarfile.TarError) as error:
                print(f"[PR DESCRIPTION] FAIL: could not read the tree of {args.commit}: {error}")
                return 1
        findings: list[str] = []
        check_domains_are_described(body, findings)
        check_counts_are_described(body, findings)
        check_head_is_bound(body, findings, args.head)
        check_inventory_is_bound(body, findings)
        check_machine_read_fields_are_parseable(body, findings)

    if args.json:
        print(json.dumps({"findings": findings, "status": "FAIL" if findings else "PASS"}, indent=2))
    elif findings:
        print("[PR DESCRIPTION] FAIL: the description no longer describes the branch.")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "\nThe description is what a reviewer reads instead of the tree. Update it, "
            "or the tree, until they agree."
        )
    else:
        print(f"[PR DESCRIPTION] PASS: described domains, counts, head and inventory match the {TREE}.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
