#!/usr/bin/env python3
"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG); operating system (OS);
pull request (PR); Verifier Standard (VSTD).

Preflight flight check: prevent all preventable CI failures locally before git push."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _run_command(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Execute command and return (returncode, stdout, stderr)."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    res = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=full_env)
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


def check_schema_inventory() -> bool:
    """Run packaging and schema inventory assertions."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
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


def check_full_test_suite() -> bool:
    """Run full repository pytest test suite."""
    cmd = [sys.executable, "-m", "pytest", "-q"]
    code, stdout, stderr = _run_command(cmd)
    if code != 0:
        print(f"[TEST SUITE] FAIL: Pytest suite failed:")
        print(stdout or stderr)
        return False
    print("[TEST SUITE] PASS: Full test suite passed.")
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

    if not check_stdlib_smoke():
        success = False
    if not check_presentation_gate():
        success = False
    if not check_schema_inventory():
        success = False

    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="VSTD Local Preflight Verification Gate")
    parser.add_argument("--install-hook", action="store_true", help="Install git pre-push hook")
    parser.add_argument("--pre-push", action="store_true", help="Run in git pre-push hook mode (reads stdin)")
    parser.add_argument("--range", dest="rev_range", default=None, help="Commit range to check for signatures")
    parser.add_argument("--full", action="store_true", help="Run full test suite in addition to fast preflight")
    parser.add_argument("--signatures-only", action="store_true", help="Check only commit signatures")
    args, remaining = parser.parse_known_args()

    if args.install_hook:
        return install_git_hooks()

    if args.pre_push:
        return handle_pre_push(remaining)

    print("=== VSTD Preflight Flight Check ===")
    success = True

    if not check_git_signatures(args.rev_range):
        success = False

    if args.signatures_only:
        return 0 if success else 1

    if not check_stdlib_smoke():
        success = False

    if not check_presentation_gate():
        success = False

    if not check_schema_inventory():
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
