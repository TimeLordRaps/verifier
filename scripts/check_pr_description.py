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
import ast
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
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
    "carriers", "mainstay_certification", "verifier_bootstrap", "verifier_execution",
})

# Either dash spelling is accepted; the description uses an en dash.
DASH = r"[–—-]"
SOURCE_FEATURE_MANIFEST = "docs/PR_SOURCE_FEATURES.json"
MAX_SOURCE_FEATURE_MANIFEST_BYTES = 4 * 1024 * 1024


def _fail(findings: list[str], message: str) -> None:
    findings.append(message)


def source_feature_inventory(root: Path, base: str, target: str | None = None) -> dict:
    """Bind every changed source file and changed Python definition to exact bytes.

    No candidate code is imported. Private definitions count too. This is structural
    coverage, not a proof that a summary describes every semantic change truthfully.
    """
    def git(*args: str) -> bytes:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=60)
        result.check_returncode()
        return result.stdout

    base_oid = git("rev-parse", "--verify", "--end-of-options", base + "^{commit}").decode().strip()
    target_oid = git("rev-parse", "--verify", "--end-of-options", (target or "HEAD") + "^{commit}").decode().strip()
    # A base must precede the reviewed head; an unrelated or future base cannot hide changes.
    git("merge-base", "--is-ancestor", base_oid, target_oid)

    roots = ("src", "scripts", ".github", "pyproject.toml")

    def in_scope(name: str) -> bool:
        return name.startswith(("src/", "scripts/", ".github/workflows/")) or name == "pyproject.toml"

    def snapshot(revision: str) -> dict[str, bytes]:
        available = set(git("ls-tree", "--name-only", revision).decode().splitlines())
        selected = [name for name in roots if name in available]
        if not selected:
            return {}
        raw = git("archive", "--format=tar", revision, *selected)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            result = {}
            for member in archive.getmembers():
                if not in_scope(member.name):
                    continue
                if member.isfile():
                    if member.size > 16 * 1024 * 1024:
                        raise ValueError("source file exceeds inventory byte bound")
                    result[member.name] = archive.extractfile(member).read()
                elif not member.isdir():
                    raise ValueError("source inventory refuses symbolic links and special files")
            return result

    before = snapshot(base_oid)
    if target:
        after = snapshot(target_oid)
    else:
        names = git("ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", *roots).decode().split("\0")
        after = {}
        for name in set(names) - {""}:
            if not in_scope(name):
                continue
            path = root / name
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("source inventory refuses paths outside the repository")
            if not path.exists():
                continue
            if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("source inventory requires bounded regular files")
            after[name] = path.read_bytes()

    def definitions(raw: bytes | None, name: str) -> dict[str, str]:
        if raw is None or not name.endswith(".py"):
            return {}
        tree = ast.parse(raw, filename=name)
        found = {}
        def visit(nodes: list, prefix: str = "") -> None:
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    key = prefix + node.name
                    found[key] = ast.dump(node, include_attributes=False)
                    if isinstance(node, ast.ClassDef):
                        visit(node.body, key + ".")
        visit(tree.body)
        return found

    rows = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        previous, current = definitions(old, name), definitions(new, name)
        symbols = sorted(key for key in set(previous) | set(current) if previous.get(key) != current.get(key))
        rows.append({"path": name, "sha256": hashlib.sha256(new).hexdigest() if new is not None else None,
                     "symbols": symbols})
    return {"base": base_oid, "target": target_oid if target else "WORKTREE:" + target_oid, "files": rows}


def check_source_grounding(body: str, findings: list[str], *, root: Path = ROOT,
                           base: str = "origin/main", target: str | None = None) -> None:
    """Require complete source records for each declared stacked review base."""
    try:
        expected = source_feature_inventory(root, base, target)
        if not expected["files"]:
            return
        blocks = re.findall(r"^```vstd-source-features\s*\n(.*?)^```[ \t]*$", body, re.MULTILINE | re.DOTALL)
        if not 1 <= len(blocks) <= 2:
            raise ValueError("one or two vstd-source-features blocks are required")
        def unique(pairs: list) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate source coverage field")
                result[key] = value
            return result
        records = [json.loads(block, object_pairs_hook=unique) for block in blocks]
        bases: set[str] = set()
        for record in records:
            if type(record) is not dict or set(record) not in (
                {"base", "target", "files"}, {"base", "target", "manifest"}
            ):
                raise ValueError("invalid source coverage record fields")
            declared_base = record["base"]
            if (type(declared_base) is not str
                    or not re.fullmatch(r"[0-9a-f]{40}", declared_base)
                    or declared_base in bases):
                raise ValueError("source coverage bases must be distinct commit identifiers")
            bases.add(declared_base)
        if expected["base"] not in bases:
            raise ValueError("source coverage base or target is stale")

        for record in records:
            checked = (expected if record["base"] == expected["base"] else
                       source_feature_inventory(root, record["base"], target))
            if record["target"] != checked["target"]:
                raise ValueError("source coverage base or target is stale")
            if "manifest" in record:
                locator = record["manifest"]
                if (type(locator) is not dict or set(locator) != {"path", "sha256"}
                        or locator["path"] != SOURCE_FEATURE_MANIFEST
                        or type(locator["sha256"]) is not str
                        or not re.fullmatch(r"[0-9a-f]{64}", locator["sha256"])):
                    raise ValueError("source coverage manifest locator is invalid")
                if target is None:
                    manifest_path = root / SOURCE_FEATURE_MANIFEST
                    if (manifest_path.is_symlink() or not manifest_path.is_file()
                            or not manifest_path.resolve().is_relative_to(root.resolve())
                            or manifest_path.stat().st_size > MAX_SOURCE_FEATURE_MANIFEST_BYTES):
                        raise ValueError("source coverage manifest must be a bounded regular file")
                    raw = manifest_path.read_bytes()
                else:
                    object_name = checked["target"] + ":" + SOURCE_FEATURE_MANIFEST
                    size = subprocess.run(["git", "-C", str(root), "cat-file", "-s", object_name],
                                          capture_output=True, timeout=30)
                    size.check_returncode()
                    if int(size.stdout) > MAX_SOURCE_FEATURE_MANIFEST_BYTES:
                        raise ValueError("source coverage manifest byte bound exceeded")
                    archived = subprocess.run(["git", "-C", str(root), "show", object_name],
                                              capture_output=True, timeout=30)
                    archived.check_returncode()
                    raw = archived.stdout
                if hashlib.sha256(raw).hexdigest() != locator["sha256"]:
                    raise ValueError("source coverage manifest digest differs")
                document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
                if type(document) is not dict or set(document) != {"base", "files"}:
                    raise ValueError("source coverage manifest fields are invalid")
                record = {"base": document["base"], "target": record["target"],
                          "files": document["files"]}
                if record["base"] != checked["base"]:
                    raise ValueError("source coverage manifest base differs")
            if type(record["files"]) is not list:
                raise ValueError("source coverage files must be a list")
            observed = {}
            for row in record["files"]:
                if type(row) is not dict or set(row) != {"path", "sha256", "symbols", "summary", "limits"}:
                    raise ValueError("each source row needs path, sha256, symbols, summary and limits")
                if type(row["path"]) is not str or row["path"] in observed:
                    raise ValueError("invalid or duplicate source path")
                if any(type(row[key]) is not str or not row[key].strip() for key in ("summary", "limits")):
                    raise ValueError("source coverage requires a behavioral summary and explicit limits")
                observed[row["path"]] = {key: row[key] for key in ("path", "sha256", "symbols")}
            wanted = {row["path"]: row for row in checked["files"]}
            for path in sorted(set(wanted) | set(observed)):
                if wanted.get(path) != observed.get(path):
                    _fail(findings, f"source feature coverage missing, stale or extraneous: {path}")
    except (OSError, ValueError, SyntaxError, UnicodeError, subprocess.SubprocessError, tarfile.TarError) as error:
        _fail(findings, f"source feature grounding failed: {error}")


def check_declared_domains(body: str, findings: list[str]) -> None:
    """Declared objects remain release scope even without an executable adapter."""
    try:
        tree = ast.parse((SOURCE / "verifier/core/profile_obligations.py").read_bytes())
        domains = {node.args[0].value for node in ast.walk(tree)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id == "_domain_rows" and node.args
                   and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)}
        for domain in sorted(domains):
            if not re.search(rf"\b{re.escape(domain)}\b", body):
                _fail(findings, f"declared domain {domain} is omitted; adapter absence does not remove release scope")
    except (OSError, SyntaxError) as error:
        _fail(findings, f"declared-domain inventory unavailable: {error}")


def domain_inventory() -> dict[str, int]:
    """Read the default computational catalogue for its separate count gate."""
    sys.path.insert(0, str(SOURCE))
    from verifier.domains.catalog import CHECKS  # noqa: PLC0415

    return {domain: len(checks) for domain, checks in CHECKS.items()}


def accountable_domain_inventory() -> dict[str, int]:
    """Read the separately discoverable native accountability checks."""
    sys.path.insert(0, str(SOURCE))
    from verifier.domains import catalog  # noqa: PLC0415

    # Older commit fixtures predate this separate catalogue. Any unregistered
    # module still fails the module-versus-catalogue check below.
    return {domain: len(checks) for domain, checks in
            getattr(catalog, "ACCOUNTABLE_CHECKS", {}).items()}


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
        # Copy regular source files only. This works on every supported Python
        # version and never delegates path or link handling to tarfile extraction.
        target_dir = into.resolve()
        for index, member in enumerate(bundle):
            if index >= 10000:
                raise ValueError("commit archive member bound exceeded")
            parts = PurePosixPath(member.name).parts
            if (not parts or parts[0] != "src" or ".." in parts
                    or "\\" in member.name or ":" in member.name):
                raise ValueError("commit archive member path is invalid")
            if member.isdir():
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("commit archive member type or size is invalid")
            destination = into.joinpath(*parts)
            if not destination.resolve().is_relative_to(target_dir):
                raise ValueError("commit archive member escapes target directory")
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("commit archive member is unavailable")
            with source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)
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
    inventory = {**domain_inventory(), **accountable_domain_inventory()}
    modules = adapter_modules()

    missing_modules = modules - set(inventory)
    if missing_modules:
        _fail(findings, (
            "adapter modules exist that the catalogue does not declare: "
            f"{', '.join(sorted(missing_modules))}. Add them to CHECKS or ACCOUNTABLE_CHECKS in "
            "src/verifier/domains/catalog.py, then describe them."
        ))
    absent_modules = set(inventory) - modules
    if absent_modules:
        _fail(findings, (
            "the catalogue declares domains with no adapter module: "
            f"{', '.join(sorted(absent_modules))}."
        ))

    try:
        from verifier.domains.catalog import COORDINATES
    except (ImportError, AttributeError):
        COORDINATES = {}
    for domain, count in sorted(inventory.items()):
        if not re.search(rf"\b{domain}\b", body):
            _fail(findings, (
                f"domain {domain} is executable but the description never names it."
            ))
            continue
        legacy_span = rf"{domain}\.1\s*{DASH}\s*(?:{domain}\.)?{count}\b"
        canonical_span = rf"{domain}-[1-6]\.\d+"
        if not (re.search(legacy_span, body) or re.search(canonical_span, body)):
            _fail(findings, (
                f"the description does not state {domain}'s coordinate range as "
                f"{domain}.1-{domain}.{count}; the catalogue declares {count} checks."
            ))

    described = set(re.findall(r"\b([A-Z][A-Z0-9]{2,})(?:\.|\-[1-8]\.)\d+\b", body))
    try:
        from scripts.check_namespace_closure import OBJECTS
    except ModuleNotFoundError:
        try:
            from check_namespace_closure import OBJECTS
        except ModuleNotFoundError:
            # Standalone commit fixtures may omit the companion gate. Keep this
            # current specification inventory in parity with its runtime enum;
            # the fallback regression also rejects unadmitted names.
            OBJECTS = frozenset({
                "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
                "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
                "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
                "AGENT", "SIM", "BOT", "TOKEN",
            })
    unknown = {name for name in described if name not in inventory and name not in OBJECTS and not name.startswith("VSTD")}
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
    parser.add_argument("--base", default="origin/main", help="trusted review base, resolved to an ancestor commit")
    parser.add_argument("--source-inventory", action="store_true", help="emit source coverage inputs; summaries and limits still require review")
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

    if args.source_inventory:
        try:
            print(json.dumps(source_feature_inventory(ROOT, args.base, args.commit), indent=2))
            return 0
        except (OSError, ValueError, SyntaxError, subprocess.SubprocessError, tarfile.TarError) as error:
            print(f"[PR DESCRIPTION] FAIL: source inventory unavailable: {error}")
            return 1

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
        check_declared_domains(body, findings)
        check_source_grounding(body, findings, root=ROOT, base=args.base, target=COMMIT or args.head)

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
