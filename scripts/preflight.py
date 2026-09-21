#!/usr/bin/env python3
"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG); operating system (OS);
pull request (PR); uniform resource locator (URL); Verifier Standard (VSTD).

Preflight flight check: prevent all preventable CI failures locally before git push."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
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
        print(f"[SIGNATURE GATE] WARNING: Unable to inspect commit range '{rev_range}': {stderr}")
        return True

    if not stdout:
        print(f"[SIGNATURE GATE] PASS: No unpushed commits in range '{rev_range}'.")
        return True

    lines = stdout.splitlines()
    unsigned: list[tuple[str, str, str, str]] = []
    checked = 0
    for line in lines:
        parts = line.split("\x00")
        if len(parts) != 4:
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
        print(f"[PRESENTATION GATE] SKIPPED: {script} not found.")
        return True
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
    code, stdout, stderr = _run_command(cmd)
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
    """Parse pytest skip output and audit against the rubric to prevent skip slippage."""
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

    total_parsed = sum(counts.values()) + len(unclassified)
    summary_match = re.search(r"=\s*.*?\b(\d+)\s+skipped\b.*?\s*=", output)
    if not summary_match:
        summary_match = re.search(r"\b(\d+)\s+skipped\b", output)
    if summary_match:
        summary_skips = int(summary_match.group(1))
        if summary_skips > total_parsed:
            unclassified.append((
                "PYTEST_SUMMARY_DISCREPANCY",
                f"pytest reported {summary_skips} skipped tests, but audit parsed only {total_parsed} skips (unparsed skip slippage)",
            ))

    success = len(unclassified) == 0
    return success, counts, unclassified


def check_pr_description() -> bool:
    """Check that an attached pull-request description still describes this tree.

    Runs before push because the description is the artifact a reviewer reads instead
    of the tree: a push that changes the domains, the counts, the head or the file
    inventory silently invalidates it. Passing when no description can be read is
    deliberate; absence of a description is not evidence that it disagrees.
    """
    script = ROOT / "scripts" / "check_pr_description.py"
    if not script.exists():
        print("[PR DESCRIPTION GATE] FAIL: scripts/check_pr_description.py is missing")
        return False
    code, stdout, stderr = _run_command([sys.executable, str(script)])
    output = (stdout or stderr).strip()
    if output:
        print(output)
    if code != 0:
        print("[PR DESCRIPTION GATE] FAIL: update the description, or the tree, until they agree")
        return False
    print("[PR DESCRIPTION GATE] PASS")
    return True


def check_test_skips(output: str | None = None) -> bool:
    """Run skip audit and print classified skip rationale or unclassified slippage."""
    if output is None:
        cmd = [sys.executable, "-u", "-m", "pytest", "-vv", "-s", "--durations=10", "--timeout=60", "-rs", "tests/"]
        code, stdout, stderr = _run_command(cmd)
        output = stdout + "\n" + stderr

    success, counts, unclassified = audit_test_skips(output)
    total_skips = sum(counts.values()) + len(unclassified)

    if not success:
        print(f"[SKIP AUDIT] FAIL: Found {len(unclassified)} unclassified test skip(s) risking skip slippage:")
        for loc, reason in unclassified:
            print(f"  - [{loc}] {reason}")
        print("\nRemedy:")
        print("  Every skipped test must be justified against docs/TEST_SKIP_RUBRIC.md.")
        print("  Either update the test skip message with a rubric tag like [OS_CAPABILITY_GUARD],")
        print("  or ensure the rationale clearly documents the missing platform capability/dependency.")
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
    """Run full repository pytest test suite and audit test skips."""
    cmd = [sys.executable, "-u", "-m", "pytest", "-vv", "-s", "--durations=10", "--timeout=60", "-rs"]
    code, stdout, stderr = _run_command(cmd)
    if code != 0:
        print(f"[TEST SUITE] FAIL: Pytest suite failed:")
        print(stdout or stderr)
        return False
    print("[TEST SUITE] PASS: Full test suite passed.")
    if stdout:
        if not check_test_skips(stdout):
            return False
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
    ZERO = "0000000000000000000000000000000000000000"
    rev_ranges: list[str] = []

    if not sys.stdin.isatty():
        for line in sys.stdin:
            parts = line.strip().split()
            if len(parts) == 4:
                local_ref, local_oid, remote_ref, remote_oid = parts
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
    if not check_pr_description():
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

    if not check_pr_description():
        success = False

    if args.full:
        if not check_full_test_suite():
            success = False

    if success:
        print("\n[PREFLIGHT] ALL CHECKS PASSED: Safe to push to remote.")
        return 0
    else:
        print("\n[PREFLIGHT] PREFLIGHT FAILED: Do not push to remote until resolved.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
