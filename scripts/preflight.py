#!/usr/bin/env python3
"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG);
Java unit test report format (JUnit); operating system (OS); pull request (PR);
uniform resource locator (URL); Verifier Standard (VSTD).

Check declared local gates before git push. Normal preflight exits 0 for passed
local checks, 1 for a failed check, and 2 when the pull-request description is
unavailable or its result cannot be established. Passing local checks grants no
push authority and does not replace the strict pre-push or hosted gates.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading

try:
    from scripts.check_public_estate_sync import (
        check_documentation_version_references, installation_documentation_version,
    )
except ModuleNotFoundError:
    from check_public_estate_sync import (
        check_documentation_version_references, installation_documentation_version,
    )


ROOT = Path(__file__).resolve().parents[1]


def _run_command(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Execute command and return (returncode, stdout, stderr)."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    if "pytest" in cmd:
        # Preserve live test names and traces while retaining skip-audit evidence.
        process = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, env=full_env)
        def stop() -> None:
            print("[TEST STOP LOSS] total execution exceeded 600 seconds", flush=True)
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], timeout=10)
            else:
                process.kill()
        timer = threading.Timer(600, stop)
        timer.daemon = True
        timer.start()
        lines = []
        try:
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="", flush=True)
                lines.append(line)
            return process.wait(timeout=10), "".join(lines), ""
        finally:
            timer.cancel()
    res = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=full_env, timeout=120)
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def check_git_signatures(rev_range: str | None = None) -> bool:
    """Verify that every commit in the specified rev_range (or unpushed commits) has a valid GPG signature.

    Format %G? outputs:
    G: Good (valid) signature
    B: Bad signature
    U: Good signature with unknown/untrusted key validity
    X: Good signature that has expired
    Y: Good signature made by an expired key
    R: Good signature made by a revoked key
    E: Signature cannot be checked
    N: No signature (unsigned)
    """
    if not rev_range:
        code, out, _ = _run_command(["git", "rev-parse", "--verify", "origin/main"])
        if code == 0:
            rev_range = "origin/main..HEAD"
        else:
            code, out, _ = _run_command(["git", "rev-parse", "--abbrev-ref", "@{upstream}"])
            if code == 0 and out:
                rev_range = f"{out}..HEAD"
            else:
                rev_range = "HEAD~1..HEAD"

    cmd = ["git", "log", rev_range, "--format=%H%x00%G?%x00%an%x00%s"]
    code, stdout, stderr = _run_command(cmd)
    if code != 0:
        print(f"[SIGNATURE GATE] FAIL: Unable to inspect commit range '{rev_range}': {stderr}")
        print("  Signature status was not established, so the range cannot be cleared.")
        return False

    if not stdout:
        code, count, stderr = _run_command(["git", "rev-list", "--count", rev_range])
        if code != 0 or count.strip() != "0":
            print(f"[SIGNATURE GATE] FAIL: No signature rows were returned for '{rev_range}', but its commit "
                  f"count is not established as zero ({count.strip() or stderr or 'no output'}).")
            return False
        print(f"[SIGNATURE GATE] PASS: No unpushed commits in range '{rev_range}'.")
        return True

    lines = stdout.splitlines()
    unsigned: list[tuple[str, str, str, str]] = []
    unparsed = 0
    checked = 0
    for line in lines:
        parts = line.split("\x00")
        if len(parts) != 4:
            unparsed += 1
            continue
        commit_hash, sig_status, author, subject = parts
        checked += 1
        # G (good) or U (good with untrusted cert) are valid cryptographic signatures
        if sig_status not in ("G", "U"):
            unsigned.append((commit_hash, sig_status, author, subject))

    if unsigned:
        print(f"[SIGNATURE GATE] FAIL: Found {len(unsigned)} commit(s) without valid GPG signatures in {rev_range}:")
        for h, s, author, subj in unsigned:
            status_desc = {
                "N": "UNSIGNED",
                "B": "BAD SIGNATURE",
                "E": "CHECK ERROR",
                "X": "EXPIRED SIGNATURE",
                "Y": "EXPIRED KEY",
                "R": "REVOKED KEY",
            }.get(s, f"INVALID ({s})")
            print(f"  - [{status_desc}] {h[:10]} by {author}: {subj}")
        print("\nRemedy:")
        print("  Every commit entering main must be GPG signed to pass branch protection.")
        print("  Re-sign single commit: git commit --amend -S --no-edit")
        print("  Re-sign branch:        git rebase origin/main --exec 'git commit --amend -S --no-edit'")
        return False

    if unparsed:
        print(f"[SIGNATURE GATE] FAIL: {unparsed} log row(s) in {rev_range} could not be parsed as "
              "signature records, so their signature status was not established.")
        return False

    print(f"[SIGNATURE GATE] PASS: All {checked} commit(s) in {rev_range} have verified GPG signatures.")
    return True


def check_stdlib_smoke() -> bool:
    """Mirror the CI stdlib-smoke job to guarantee zero required third-party runtime dependencies."""
    python_code = (
        "import verifier; "
        "from verifier.core.run import load_manifest; "
        "print(f'stdlib-smoke verified: verifier {verifier.__version__}')"
    )
    cmd = [sys.executable, "-S", "-c", python_code]
    env = {"PYTHONPATH": str(ROOT / "src")}
    code, stdout, stderr = _run_command(cmd, env=env)
    if code != 0:
        print(f"[STDLIB SMOKE] FAIL: Standard library purity violated:")
        print(stderr or stdout)
        return False
    print(f"[STDLIB SMOKE] PASS: {stdout}")
    return True


def check_presentation_gate() -> bool:
    """Run presentation, documentation, boundary leaks, and public estate sync checks."""
    script = ROOT / "scripts" / "check_presentation.py"
    if not script.exists():
        print(f"[PRESENTATION GATE] FAIL: {script} not found, so the presentation, boundary and estate "
              "sync checks did not run.")
        return False
    code, stdout, stderr = _run_command([sys.executable, str(script)])
    if code != 0:
        print(f"[PRESENTATION GATE] FAIL: check_presentation.py failed:")
        if stdout:
            print(stdout)
        if stderr:
            print(stderr)
        return False
    print("[PRESENTATION GATE] PASS: Presentation, boundary, and estate sync verified.")
    return True


def check_readme_version() -> bool:
    """Verify that README.md install commands and release coordinates match pyproject.toml."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = pyproject.split("[project]", 1)
    project_text = "" if len(project_section) != 2 else project_section[1].split("\n[", 1)[0]
    m = re.search(r'^version\s*=\s*"([^"]+)"$', project_text, re.MULTILINE)
    if not m:
        print("[README VERSION] FAIL: Unable to parse version from pyproject.toml.")
        return False
    expected = m.group(1)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    try:
        released = installation_documentation_version(ROOT, expected)
    except ValueError as exc:
        print(f"[README VERSION] FAIL: {exc}")
        return False

    errors: list[str] = []
    pip_cmd = f'python -m pip install "verifier-standard=={released}"'
    if pip_cmd not in readme:
        errors.append(f"README.md missing pinned install command: {pip_cmd!r}")

    source_coord = f"At the version {expected} source coordinate"
    if source_coord not in readme:
        errors.append(f"README.md missing source coordinate statement: {source_coord!r}")

    release_stmt = f"Version {released} is the current release"
    if release_stmt not in readme:
        errors.append(f"README.md missing current release statement: {release_stmt!r}")

    tag_url = f"https://github.com/TimeLordRaps/verifier/releases/tag/v{released}"
    if tag_url not in readme:
        errors.append(f"README.md missing release tag URL: {tag_url!r}")

    if errors:
        print(f"[README VERSION] FAIL: Version synchronization failure in README.md (expected {expected}):")
        for err in errors:
            print(f"  - {err}")
        return False

    print(f"[README VERSION] PASS: README.md versions synchronized with pyproject.toml ({expected}).")
    return True


def check_docs_versions() -> bool:
    """Verify that all documentation files with pinned install/release/clone commands match pyproject.toml."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = pyproject.split("[project]", 1)
    project_text = "" if len(project_section) != 2 else project_section[1].split("\n[", 1)[0]
    m = re.search(r'^version\s*=\s*"([^"]+)"$', project_text, re.MULTILINE)
    if not m:
        print("[DOCS VERSIONS] FAIL: Unable to parse version from pyproject.toml.")
        return False
    expected = m.group(1)

    errors = check_documentation_version_references(ROOT, expected)

    if errors:
        print(f"[DOCS VERSIONS] FAIL: Documentation version synchronization failure (expected {expected}):")
        for err in errors:
            print(f"  - {err}")
        return False

    print(f"[DOCS VERSIONS] PASS: Documentation estate version references synchronized with pyproject.toml ({expected}).")
    return True


def check_schema_inventory() -> bool:
    """Run packaging and schema inventory assertions."""
    cmd = [
        sys.executable,
        "-u",
        "-m",
        "pytest",
        "-vv", "-s", "--durations=10", "--timeout=60",
        "tests/test_packaged_specifications.py",
        "tests/test_release_artifacts.py",
        "-k",
        "schema",
    ]
    nested_env = None
    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD"):
        plugins = [
            name.strip()
            for name in os.environ.get("PYTEST_PLUGINS", "").split(",")
            if name.strip()
        ]
        if "pytest_timeout" not in plugins:
            plugins.append("pytest_timeout")
        nested_env = {"PYTEST_PLUGINS": ",".join(plugins)}

    code, stdout, stderr = _run_command(cmd, env=nested_env)
    if code != 0:
        print(f"[SCHEMA INVENTORY] FAIL: Schema/packaged specification tests failed:")
        print(stdout or stderr)
        return False
    print("[SCHEMA INVENTORY] PASS: Schema inventories and packaged specifications match.")
    return True


TEST_SKIP_RUBRIC_CATEGORIES = (
    "OS_CAPABILITY_GUARD",
    "OPTIONAL_DEPENDENCY_ABSENT",
    "EXTERNAL_SERVICE_BOUNDARY",
    "ARCHITECTURAL_PLATFORM_UNSUPPORTED",
    "HARDWARE_DEVICE_UNAVAILABLE",
    "PRIVILEGE_OR_CREDENTIAL_BOUNDARY",
    "PERFORMANCE_OR_DURATION_EXCLUSION",
    "QUARANTINED_DEFECT",
)


def classify_skip_reason(reason: str) -> str:
    """Classify a test skip reason string against the formal rubric in docs/TEST_SKIP_RUBRIC.md."""
    stripped = reason.strip()
    for category in TEST_SKIP_RUBRIC_CATEGORIES:
        if (
            stripped.startswith(f"[{category}]")
            or stripped.startswith(f"[`{category}`]")
            or stripped.startswith(f"{category}:")
            or stripped.startswith(f"`{category}`:")
            or stripped.startswith(f"{category} -")
        ):
            return category

    lower = stripped.lower()
    if any(
        term in lower
        for term in (
            "symlink",
            "mkfifo",
            "fifo",
            "first-in, first-out",
            "named pipe",
            "unix",
            "posix",
            "errno=",
            "winerror=",
        )
    ):
        return "OS_CAPABILITY_GUARD"
    if any(term in lower for term in ("optional", "extra", "scitt", "seal", "dependency")):
        return "OPTIONAL_DEPENDENCY_ABSENT"
    if any(term in lower for term in ("network", "service", "endpoint", "offline", "air-gap")):
        return "EXTERNAL_SERVICE_BOUNDARY"
    if any(term in lower for term in ("architecture", "arm64", "x86_64", "endian")):
        return "ARCHITECTURAL_PLATFORM_UNSUPPORTED"
    if any(term in lower for term in ("hardware", "device", "gpu", "tpu", "hsm", "accelerator")):
        return "HARDWARE_DEVICE_UNAVAILABLE"
    if any(term in lower for term in ("privilege", "admin", "root", "credential", "secret", "permission")):
        return "PRIVILEGE_OR_CREDENTIAL_BOUNDARY"
    if any(term in lower for term in ("slow", "duration", "benchmark", "soak", "stress", "performance")):
        return "PERFORMANCE_OR_DURATION_EXCLUSION"
    if any(term in lower for term in ("quarantin", "issue", "bug", "defect", "http://", "https://")):
        return "QUARANTINED_DEFECT"
    return "UNCLASSIFIED"


def audit_test_skips(output: str) -> tuple[bool, dict[str, int], list[tuple[str, str]]]:
    """Reject unaccounted skips and every xfail/xpass suppression.

    The skip rubric can classify an unrun capability boundary.  It cannot turn
    an expected failure into passing coverage.  Pytest does not emit xfail or
    xpass detail under every reporting flag, so both detail lines and terminal
    summary counts are inspected.  Summary-only suppression counts remain an
    actionable discrepancy instead of being reported as a clean run.
    """
    counts: dict[str, int] = {category: 0 for category in TEST_SKIP_RUBRIC_CATEGORIES}
    unclassified: list[tuple[str, str]] = []

    skip_pattern = re.compile(
        r"^SKIPPED(?:\s+\[(\d+)\])?\s+((?:[A-Za-z]:)?[^:\r\n]+(?::\d+|::[^\r\n:]+)?):\s*(.*)$",
        re.MULTILINE,
    )

    for match in skip_pattern.finditer(output):
        count_str, loc, reason = match.groups()
        count = int(count_str) if count_str else 1
        category = classify_skip_reason(reason)
        if category in counts:
            counts[category] += count
        else:
            unclassified.append((loc, reason))

    # Keep the skip denominator separate.  Xfail/xpass findings added below
    # must never make a missing SKIPPED detail line look accounted for.
    parsed_skip_count = sum(counts.values()) + len(unclassified)

    xfail_pattern = re.compile(r"^XFAIL\s+([^\r\n]+)$", re.MULTILINE)
    xpass_pattern = re.compile(r"^XPASS\s+([^\r\n]+)$", re.MULTILINE)
    xfail_details = xfail_pattern.findall(output)
    xpass_details = xpass_pattern.findall(output)
    for detail in xfail_details:
        unclassified.append((
            "PYTEST_XFAIL_PRESENT",
            "Expected failure is not passing coverage; fix the underlying test "
            f"and remove the xfail marker: {detail.strip()}",
        ))
    for detail in xpass_details:
        unclassified.append((
            "PYTEST_XPASS_PRESENT",
            "Non-strict XPASS leaves a stale suppression marker; remove the "
            f"marker and rerun the unsuppressed test: {detail.strip()}",
        ))

    strict_xpass = re.findall(r"\[XPASS\(strict\)\](?:\s*([^\r\n]*))?", output)
    for detail in strict_xpass:
        suffix = f": {detail.strip()}" if detail.strip() else ""
        unclassified.append((
            "PYTEST_STRICT_XPASS_PRESENT",
            "Strict XPASS is a failed stale-suppression gate; remove the marker "
            "only after the test passes without suppression" + suffix,
        ))

    summary_match = re.search(r"=\s*.*?\b(\d+)\s+skipped\b.*?\s*=", output)
    if not summary_match:
        summary_match = re.search(r"\b(\d+)\s+skipped\b", output)
    if summary_match:
        summary_skips = int(summary_match.group(1))
        if summary_skips != parsed_skip_count:
            unclassified.append((
                "PYTEST_SUMMARY_DISCREPANCY",
                f"pytest reported {summary_skips} skipped tests, but audit parsed only {parsed_skip_count} skips (unparsed skip slippage)",
            ))

    for label, detail_count, code in (
        ("xfailed", len(xfail_details), "PYTEST_XFAIL_SUMMARY_DISCREPANCY"),
        ("xpassed", len(xpass_details), "PYTEST_XPASS_SUMMARY_DISCREPANCY"),
    ):
        summary = re.search(rf"\b(\d+)\s+{label}\b", output)
        if summary and int(summary.group(1)) != detail_count:
            unclassified.append((
                code,
                f"pytest reported {summary.group(1)} {label} test(s), but the "
                f"audit observed {detail_count} detail line(s); xfail/xpass "
                "cannot be omitted from a complete-clean-run claim",
            ))

    success = len(unclassified) == 0
    return success, counts, unclassified


def check_pr_description() -> bool | None:
    """Check the attached description; preserve unavailable evidence as None.

    The checker can exit successfully without reading a description. Only its
    explicit machine-readable result establishes agreement. The strict push
    path separately selects the repository, branch and proposed commit.
    """
    script = ROOT / "scripts" / "check_pr_description.py"
    if not script.exists():
        print("[PR DESCRIPTION GATE] FAIL: scripts/check_pr_description.py is missing")
        return False
    try:
        code, stdout, stderr = _run_command([sys.executable, str(script), "--json"])
    except (OSError, subprocess.SubprocessError):
        print("[PR DESCRIPTION GATE] UNKNOWN: description checker unavailable")
        return None
    output = (stdout or stderr).strip()
    if output:
        print(output)
    if code != 0:
        print("[PR DESCRIPTION GATE] FAIL: update the description, or the tree, until they agree")
        return False
    try:
        report = json.loads(stdout)
    except (ValueError, TypeError):
        report = None
    if (type(report) is not dict or set(report) != {"status", "findings"}
            or report["status"] not in ("PASS", "FAIL")
            or type(report["findings"]) is not list
            or any(type(finding) is not str for finding in report["findings"])):
        print("[PR DESCRIPTION GATE] UNKNOWN: no explicit description-check result")
        return None
    if report["status"] == "FAIL" or report["findings"]:
        print("[PR DESCRIPTION GATE] FAIL: the description does not establish agreement")
        return False
    print("[PR DESCRIPTION GATE] PASS")
    return True


ZERO_OID = "0000000000000000000000000000000000000000"

GITHUB_REMOTE = re.compile(
    r"^(?:https://(?:[^@/\s]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"(?P<repository>[^/\s]+/[^/\s]+?)(?:\.git)?/?$"
)


def github_repository(url: str) -> str | None:
    """`OWNER/NAME` of a GitHub remote URL, or None for any other remote."""
    match = GITHUB_REMOTE.match(url.strip())
    if not match:
        return None
    repo = match.group("repository")
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
        return None
    return repo


def open_pull_requests(repository: str, branch: str) -> list[int]:
    """Open pull requests in `repository` whose head is `branch` of that same repository.

    A pull request from a fork can carry the same branch name; pushing here does not
    move it, so it is filtered out. Raises RuntimeError when gh cannot answer.
    """
    code, stdout, _ = _run_command([
        "gh", "pr", "list", "--repo", repository, "--head", branch, "--state", "open",
        "--json", "number,headRepository,headRepositoryOwner",
    ])
    if code != 0:
        # Command output can include credentials from a failed remote request.
        raise RuntimeError(f"gh exited with status {code}")
    owner, name = repository.lower().split("/", 1)
    numbers = []
    for pull in json.loads(stdout or "[]"):
        head_owner = ((pull.get("headRepositoryOwner") or {}).get("login") or "").lower()
        head_name = ((pull.get("headRepository") or {}).get("name") or "").lower()
        if (head_owner, head_name) == (owner, name):
            numbers.append(int(pull["number"]))
    return sorted(numbers)


def check_pr_descriptions_for_push(pushes: list[tuple[str, str, str, str]],
                                   hook_args: list[str]) -> bool:
    """Refuse a push that would leave an open pull request's description behind it.

    Pull requests are looked up by the branch being written on the remote, not the
    local branch. `git push origin work:feature` moves the pull request whose head is
    `feature`, and asking about `work` finds nothing. Until 2026-09-23 this gate asked
    about the local branch and passed on exactly that push.

    Two checks run on each pull request the push moves. The first refuses the push
    when the description is word for word the one in force when the pull request's
    current head was pushed: every push must come with a revised description, so
    whoever pushes, person or model, is stopped until they revise it. The second
    checks what the description says, against the pushed commit's own tree, so a push
    from a checkout at another commit, or with uncommitted changes, is judged on what
    is published. The description therefore has to be revised, and bind the new head,
    before the push: update it first, then push. A pull request that lives in another
    repository (one opened from this repository into an upstream) is not found here;
    the hosted pr-description workflow judges it with its own recorded-event checks.

    Anything that cannot be answered fails the push. A question gh could not answer
    is not a no.
    """
    branches = [
        (remote_ref[len("refs/heads/"):], local_oid)
        for _local_ref, local_oid, remote_ref, _remote_oid in pushes
        if local_oid != ZERO_OID and remote_ref.startswith("refs/heads/")
    ]
    if not branches:
        print("[PR DESCRIPTION GATE] PASS: this push moves no branch head.")
        return True

    url = hook_args[1] if len(hook_args) > 1 else ""
    if not url and hook_args:
        code, stdout, _ = _run_command(["git", "remote", "get-url", "--push", hook_args[0]])
        url = stdout if code == 0 else ""
    if not url:
        print("[PR DESCRIPTION GATE] FAIL: cannot tell which repository this push writes to, "
              "so cannot tell which pull requests it moves.")
        return False
    repository = github_repository(url)
    if repository is None:
        # The URL is not printed: a remote URL can carry a credential.
        print("[PR DESCRIPTION GATE] PASS: the push goes to a remote that is not on GitHub, "
              "where no pull request can track a branch.")
        return True
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repository):
        print("[PR DESCRIPTION GATE] FAIL: invalid GitHub repository name format.")
        return False

    script = ROOT / "scripts" / "check_pr_description.py"
    changed = ROOT / "scripts" / "check_pr_description_revision.py"
    success = True
    for branch, oid in branches:
        try:
            numbers = open_pull_requests(repository, branch)
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError):
            print("[PR DESCRIPTION GATE] FAIL: could not query open pull requests "
                  "for the pushed branch.")
            print("  Check gh authentication and retry; the push remains blocked.")
            success = False
            continue
        if not numbers:
            print("[PR DESCRIPTION GATE] PASS: no open pull request tracks "
                  "the pushed branch.")
            continue
        for number in numbers:
            code, stdout, stderr = _run_command([
                sys.executable, str(changed), "--pr", str(number), "--repo", repository,
            ])
            output = (stdout or stderr).strip()
            if output:
                print(output)
            if code != 0:
                print(f"[PR DESCRIPTION GATE] FAIL: it is not established that pull request "
                      f"#{number}'s description was revised since its current head was pushed. "
                      f"Revise it to describe {oid[:12]}, then push again.")
                success = False
            code, stdout, stderr = _run_command([
                sys.executable, str(script), "--pr", str(number), "--repo", repository,
                "--commit", oid, "--require-pull-request", "--pre-push-pending-run",
            ])
            output = (stdout or stderr).strip()
            if output:
                print(output)
            if code != 0:
                print(f"[PR DESCRIPTION GATE] FAIL: after this push, pull request #{number} "
                      f"would describe a tree other than {oid[:12]}. Update its description "
                      "to describe that commit, then push again.")
                success = False
            else:
                print(f"[PR DESCRIPTION GATE] PASS: pull request #{number} describes {oid[:12]}.")
    return success


def check_test_skips(output: str | None = None) -> bool:
    """Run skip/xfail audit and reject suppression as clean coverage."""
    if output is None:
        cmd = [sys.executable, "-u", "-m", "pytest", "-vv", "-s", "--durations=10", "--timeout=60", "-rs", "tests/"]
        code, stdout, stderr = _run_command(cmd)
        if code != 0:
            print(f"[SKIP AUDIT] FAIL: pytest exited with code {code}; skips cannot be audited over a failed run.")
            return False
        output = stdout + "\n" + stderr

    if not output.strip():
        print("[SKIP AUDIT] FAIL: the test run produced no output; skips cannot be audited over an empty run.")
        return False

    success, counts, unclassified = audit_test_skips(output)
    total_skips = sum(counts.values()) + len(unclassified)

    if not success:
        print(
            f"[SKIP AUDIT] FAIL: Found {len(unclassified)} unclosed "
            "skip/xfail/xpass finding(s):"
        )
        for loc, reason in unclassified:
            print(f"  - [{loc}] {reason}")
        print("\nRemedy:")
        print("  Every skipped test must be justified against docs/TEST_SKIP_RUBRIC.md.")
        print("  Either update the test skip message with a rubric tag like [OS_CAPABILITY_GUARD],")
        print("  or ensure the rationale clearly documents the missing platform capability/dependency.")
        print(
            "  XFAIL and XPASS have no passing-coverage rubric: repair the "
            "underlying behavior, remove the marker, and rerun the test."
        )
        return False

    if total_skips == 0:
        print("[SKIP AUDIT] PASS: Zero tests skipped (complete clean run).")
        return True

    print(f"[SKIP AUDIT] PASS: All {total_skips} skipped test(s) accounted for under rubric categories:")
    for category, count in counts.items():
        if count > 0:
            print(f"  - {category}: {count} test(s)")
    return True


def check_full_test_suite() -> bool:
    """Run full repository pytest test suite, audit test skips, and scan its report.

    The hosted base job publishes the suite's JUnit report only once
    `check_release_boundary.py` passes it, and a report is not the source it came
    from: a parametrized test's default id is its parameters' own text, so an address
    joined at run time to keep a test file clean is written into the report whole.
    The report is therefore written and scanned here too, so that a push is not the
    first place a leak in the evidence shows.
    """
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "base-contracts.xml"
        cmd = [sys.executable, "-u", "-m", "pytest", "-vv", "-s", "--durations=10", "--timeout=60", "-rs",
               "-p", "scripts.pytest_public_evidence", f"--junitxml={report}"]
        code, stdout, stderr = _run_command(cmd)
        if code != 0:
            print(f"[TEST SUITE] FAIL: Pytest suite failed:")
            print(stdout or stderr)
            return False
        print("[TEST SUITE] PASS: Full test suite passed.")
        if stdout:
            if not check_test_skips(stdout):
                return False
        code, stdout, stderr = _run_command(
            [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(report)])
        if code != 0:
            print("[TEST EVIDENCE] FAIL: the suite's report fails the release boundary the hosted "
                  "run applies before publishing it:")
            print(stdout or stderr)
            return False
        print("[TEST EVIDENCE] PASS: the suite's report passes the release boundary.")
    return True


def install_git_hooks() -> int:
    """Install or update .git/hooks/pre-push."""
    code, git_dir, _ = _run_command(["git", "rev-parse", "--git-path", "hooks"])
    if code != 0 or not git_dir:
        print("[HOOK INSTALL] Error: Unable to determine git hooks directory.")
        return 1

    hooks_dir = Path(git_dir).resolve()
    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_push = hooks_dir / "pre-push"

    py_exe = sys.executable.replace("\\", "/")

    pre_push_script = f"""#!/bin/sh
# VSTD Automated Pre-Push Flight Check Gate
# Prevents unsigned commits, schema divergence, and boundary leaks before push.

PYTHON_BIN="{py_exe}"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN="python"
fi

"$PYTHON_BIN" scripts/preflight.py --pre-push "$@"
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "[PREFLIGHT] ABORTING PUSH: Preflight checks failed. Fix the issues above before pushing."
    exit 1
fi

exit 0
"""
    pre_push.write_text(pre_push_script, encoding="utf-8", newline="\n")
    try:
        import stat
        pre_push.chmod(pre_push.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    print(f"[HOOK INSTALL] Successfully installed pre-push hook at: {pre_push}")
    return 0


def handle_pre_push(args: list[str]) -> int:
    """Handle invocation from git pre-push hook, parsing stdin ref updates."""
    ZERO = ZERO_OID
    rev_ranges: list[str] = []
    pushes: list[tuple[str, str, str, str]] = []

    if not sys.stdin.isatty():
        for line in sys.stdin:
            parts = line.strip().split()
            if len(parts) == 4:
                local_ref, local_oid, remote_ref, remote_oid = parts
                pushes.append((local_ref, local_oid, remote_ref, remote_oid))
                if local_oid == ZERO:
                    continue
                # For PR commits, verify what is new relative to origin/main
                code, _, _ = _run_command(["git", "rev-parse", "--verify", "origin/main"])
                if code == 0:
                    rev_ranges.append(f"origin/main..{local_oid}")
                elif remote_oid != ZERO:
                    rev_ranges.append(f"{remote_oid}..{local_oid}")
                else:
                    rev_ranges.append(f"{local_oid}~1..{local_oid}")

    if not rev_ranges:
        rev_ranges.append("origin/main..HEAD")

    print("[PREFLIGHT] Running automated pre-push checks...")
    success = True
    for r in rev_ranges:
        if not check_git_signatures(r):
            success = False

    if not check_readme_version():
        success = False
    if not check_docs_versions():
        success = False
    if not check_stdlib_smoke():
        success = False
    if not check_presentation_gate():
        success = False
    if not check_schema_inventory():
        success = False
    if not check_pr_descriptions_for_push(pushes, args):
        success = False

    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="VSTD Local Preflight Verification Gate")
    parser.add_argument("--install-hook", action="store_true", help="Install git pre-push hook")
    parser.add_argument("--pre-push", action="store_true", help="Run in git pre-push hook mode (reads stdin)")
    parser.add_argument("--range", dest="rev_range", default=None, help="Commit range to check for signatures")
    parser.add_argument("--full", action="store_true", help="Run full test suite in addition to fast preflight")
    parser.add_argument("--signatures-only", action="store_true", help="Check only commit signatures")
    parser.add_argument("--audit-skips", action="store_true", help="Audit test skips against docs/TEST_SKIP_RUBRIC.md")
    args, remaining = parser.parse_known_args()

    if args.install_hook:
        return install_git_hooks()

    if args.pre_push:
        return handle_pre_push(remaining)

    if args.audit_skips:
        return 0 if check_test_skips() else 1

    print("=== VSTD Preflight Flight Check ===")
    success = True

    if not check_git_signatures(args.rev_range):
        success = False

    if args.signatures_only:
        return 0 if success else 1

    if not check_readme_version():
        success = False

    if not check_docs_versions():
        success = False

    if not check_stdlib_smoke():
        success = False

    if not check_presentation_gate():
        success = False

    if not check_schema_inventory():
        success = False

    description = check_pr_description()
    if description is False:
        success = False

    if args.full:
        if not check_full_test_suite():
            success = False

    if success:
        if description is None:
            print("\n[PREFLIGHT] UNKNOWN: local checks completed; pull-request "
                  "description agreement is not established. Strict pre-push "
                  "and hosted gates remain required.")
            return 2
        print("\n[PREFLIGHT] LOCAL CHECKS PASSED: push authorization and the "
              "strict pre-push and hosted gates remain separate requirements.")
        return 0
    else:
        print("\n[PREFLIGHT] PREFLIGHT FAILED: Do not push to remote until resolved.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
