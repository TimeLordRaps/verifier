"""Terminology: abstract syntax tree (AST); Amazon Web Services (AWS);
application programming interface (API); command-line interface (CLI);
continuous integration (CI); identifier (ID); JavaScript Object Notation (JSON);
pull request (PR); Python Package Index (PyPI);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource identifier (URI);
Verifier Standard (VSTD).

Native VSTD verification gates suite.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import fnmatch
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePath, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any, Sequence
import zipfile

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.receipt import strict_json_loads


# ---------------------------------------------------------------------------
# Path Scanner Gate
# ---------------------------------------------------------------------------

WINDOWS_DRIVE_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_%+-])[A-Za-z]:[\\/][A-Za-z0-9._\-/\\]+"
)
UNC_SHARE_PATTERN = re.compile(
    r"(?i)(?<!\\)\\\\(?![a-zA-Z]\\[a-zA-Z])[A-Za-z0-9][A-Za-z0-9._\-]{1,62}[\\/][A-Za-z0-9][A-Za-z0-9._\-/\\]+"
)
POSIX_HOME_PATTERN = re.compile(
    r"(?:^|(?<=[\s\"'<>(:=,]))/(?:home|Users)/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*"
)
FILE_URI_PATTERN = re.compile(
    r"(?i)file://(?:localhost)?/(?:[A-Za-z]:/|[A-Za-z0-9._\-]+)[A-Za-z0-9._\-/\\]*"
)

PATH_PATTERNS = (
    ("Windows drive path", WINDOWS_DRIVE_PATTERN),
    ("UNC share path", UNC_SHARE_PATTERN),
    ("POSIX user home", POSIX_HOME_PATTERN),
    ("Absolute file URI", FILE_URI_PATTERN),
)

DEFAULT_IGNORED_PARTS = frozenset({
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    ".benchmarks",
    "build",
    "dist",
    ".venv",
})

TEXT_SUFFIXES = frozenset({
    ".cff",
    ".css",
    ".html",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".svg",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".pem",
    ".key",
    ".env",
    ".cfg",
    ".ini",
    ".sh",
    ".bash",
    ".csv",
    ".tsv",
    ".rst",
    ".conf",
    ".properties",
    ".log",
})


def scan_paths_in_text(text: str, filename: str = "") -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    lines = text.splitlines()
    for line_idx, line in enumerate(lines, 1):
        for label, pattern in PATH_PATTERNS:
            for match in pattern.finditer(line):
                violations.append({
                    "file": filename,
                    "line": line_idx,
                    "label": label,
                    "match": match.group(0),
                })
    return violations


MAX_SCAN_FILE_BYTES = 16 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SCAN_FILES = 10000
ARCHIVE_SUFFIXES = (".zip", ".whl", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")


def _text_candidate(path: PurePath) -> bool:
    return (path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() == ".env"
            or path.name.lower().startswith(".env."))


def _link_like(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _scan_error(location: str, message: str) -> dict[str, Any]:
    """An incomplete scan is a finding, never a clean result."""
    return {"file": location, "location": location, "line": 0, "kind": "incomplete_scan",
            "label": message, "message": message, "match": "<unavailable>"}


def _scan_candidates(target: Path, ignored: frozenset[str], errors: list[dict[str, Any]]) -> list[Path]:
    if not target.exists() or _link_like(target):
        errors.append(_scan_error(str(target), "selected target missing or symbolic link"))
        return []
    if target.is_file():
        return [target]
    if not target.is_dir():
        errors.append(_scan_error(str(target), "selected target is not a regular file or directory"))
        return []
    candidates = []
    entries = 0

    def onerror(exc: OSError) -> None:
        errors.append(_scan_error(str(exc.filename or target), "directory traversal unavailable"))

    for root, dirs, files in os.walk(target, followlinks=False, onerror=onerror):
        entries += 1 + len(dirs) + len(files)
        if entries > MAX_SCAN_FILES:
            errors.append(_scan_error(str(target), "scan entry count bound exceeded"))
            return candidates
        kept = []
        for name in sorted(dirs):
            selected = Path(root) / name
            if name in ignored:
                continue
            try:
                if _link_like(selected):
                    errors.append(_scan_error(str(selected), "linked directory not inspected"))
                else:
                    kept.append(name)
            except OSError:
                errors.append(_scan_error(str(selected), "directory metadata unavailable"))
        dirs[:] = kept
        for name in sorted(files):
            selected = Path(root) / name
            try:
                if _link_like(selected) or not stat.S_ISREG(selected.lstat().st_mode):
                    errors.append(_scan_error(str(selected), "linked or special file not inspected"))
                else:
                    candidates.append(selected)
            except OSError:
                errors.append(_scan_error(str(selected), "file metadata unavailable"))
            if len(candidates) + len(errors) > MAX_SCAN_FILES:
                errors.append(_scan_error(str(target), "scan file count bound exceeded"))
                return candidates
    return candidates


def _read_scan_stream(stream: Any, used: list[int]) -> str:
    if used[1] >= MAX_SCAN_FILES:
        raise ValueError("scan file count bound exceeded")
    limit = min(MAX_SCAN_FILE_BYTES, MAX_SCAN_TOTAL_BYTES - used[0])
    if limit < 0:
        raise ValueError("scan total byte bound exceeded")
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("scan byte bound exceeded")
    used[0] += len(data)
    used[1] += 1
    return data.decode("utf-8")


def _read_scan_text(path: Path, used: list[int]) -> str:
    with path.open("rb") as stream:
        return _read_scan_stream(stream, used)


def run_paths_gate(target_path: Path, *, ignored_parts: frozenset[str] = DEFAULT_IGNORED_PARTS,
                   additional_excludes: list[str] | None = None) -> tuple[int, list[dict[str, Any]]]:
    violations: list[dict[str, Any]] = []
    scanned = 0
    used = [0, 0]
    for path in _scan_candidates(target_path, ignored_parts, violations):
        relative = path.relative_to(target_path).as_posix() if target_path.is_dir() else path.name
        if any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.as_posix(), pattern)
               for pattern in additional_excludes or []):
            continue
        if not _text_candidate(path):
            continue
        try:
            content = _read_scan_text(path, used)
        except (OSError, UnicodeError, ValueError) as exc:
            violations.append(_scan_error(str(path), type(exc).__name__ + ": selected text unavailable or beyond bounds"))
            continue
        scanned += 1
        violations.extend(scan_paths_in_text(content, filename=str(path)))
    if not scanned and not violations:
        violations.append(_scan_error(str(target_path), "no applicable text files inspected"))
    return scanned, violations


# ---------------------------------------------------------------------------
# AST Static Analysis Gate (anti-OOM, anti-infinite-loop)
# ---------------------------------------------------------------------------

class AstGateVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, max_iterations: int = 1000000):
        self.filename = filename
        self.max_iterations = max_iterations
        self.violations: list[dict[str, Any]] = []

    def visit_While(self, node: ast.While) -> None:
        # Detect unbounded while True without break, return, or raise
        is_const_true = False
        if isinstance(node.test, ast.Constant) and bool(node.test.value):
            is_const_true = True

        if is_const_true:
            has_exit = any(self._has_exit(n) for n in node.body)
            if not has_exit:
                self.violations.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "kind": "unbounded_infinite_loop",
                    "message": "while True loop without break, return, or raise statement",
                })
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        # Detect range(N) where N exceeds iteration ceiling
        if (
            isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Name)
            and node.iter.func.id == "range"
        ):
            args = node.iter.args
            bound = None
            if len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
                bound = args[0].value
            elif len(args) >= 2 and isinstance(args[0], ast.Constant) and isinstance(args[1], ast.Constant):
                if isinstance(args[0].value, int) and isinstance(args[1].value, int):
                    bound = abs(args[1].value - args[0].value)
            if bound is not None and bound > self.max_iterations:
                self.violations.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "kind": "loop_bound_exceeded",
                    "message": f"range bound {bound} exceeds ceiling {self.max_iterations}",
                })
        self.generic_visit(node)

    def _collection_multiplier(self, seq_node: ast.AST, mult_node: ast.AST) -> int | None:
        if not (isinstance(mult_node, ast.Constant) and isinstance(mult_node.value, int) and mult_node.value > 0):
            return None
        multiplier = mult_node.value
        if isinstance(seq_node, (ast.List, ast.Tuple)):
            base_len = max(len(seq_node.elts), 1)
            return base_len * multiplier
        elif isinstance(seq_node, ast.Constant) and isinstance(seq_node.value, (str, bytes)):
            base_len = max(len(seq_node.value), 1)
            return base_len * multiplier
        return None

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # Detect massive memory allocation via collection multiplication: [0] * N where elements > 10,000,000
        if isinstance(node.op, ast.Mult):
            elements = self._collection_multiplier(node.left, node.right)
            if elements is None:
                elements = self._collection_multiplier(node.right, node.left)
            if elements is not None and elements > 10_000_000:
                self.violations.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "kind": "memory_accumulation_cap_exceeded",
                    "message": f"large collection allocation of {elements} elements exceeds anti-OOM cap",
                })
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        for gen in node.generators:
            if (
                isinstance(gen.iter, ast.Call)
                and isinstance(gen.iter.func, ast.Name)
                and gen.iter.func.id == "range"
            ):
                args = gen.iter.args
                bound = None
                if len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
                    bound = args[0].value
                elif len(args) >= 2 and isinstance(args[0], ast.Constant) and isinstance(args[1], ast.Constant):
                    if isinstance(args[0].value, int) and isinstance(args[1].value, int):
                        bound = abs(args[1].value - args[0].value)
                if bound is not None and bound > 10_000_000:
                    self.violations.append({
                        "file": self.filename,
                        "line": node.lineno,
                        "kind": "memory_accumulation_cap_exceeded",
                        "message": f"large list comprehension allocation of {bound} elements exceeds anti-OOM cap",
                    })
        self.generic_visit(node)

    def _has_exit(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Break, ast.Return, ast.Raise)):
            return True
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.While, ast.For)):
                continue
            if self._has_exit(child):
                return True
        return False


def run_ast_gate(target_path: Path, *, max_iterations: int = 1000000,
                 ignored_parts: frozenset[str] = DEFAULT_IGNORED_PARTS) -> tuple[int, list[dict[str, Any]]]:
    """Detect listed source patterns, without proving termination or memory bounds."""
    violations: list[dict[str, Any]] = []
    if type(max_iterations) is not int or max_iterations < 1:
        return 0, [_scan_error(str(target_path), "positive iteration bound required")]
    scanned = 0
    used = [0, 0]
    for path in _scan_candidates(target_path, ignored_parts, violations):
        if path.suffix.lower() != ".py":
            continue
        try:
            content = _read_scan_text(path, used)
            tree = ast.parse(content, filename=str(path))
        except (OSError, UnicodeError, ValueError, SyntaxError, RecursionError) as exc:
            violations.append(_scan_error(str(path), type(exc).__name__ + ": Python source unavailable or invalid"))
            continue
        scanned += 1
        visitor = AstGateVisitor(str(path), max_iterations=max_iterations)
        try:
            visitor.visit(tree)
        except RecursionError:
            violations.append(_scan_error(str(path), "syntax traversal depth exceeded"))
        violations.extend(visitor.violations)
    if not scanned and not violations:
        violations.append(_scan_error(str(target_path), "no applicable Python files inspected"))
    return scanned, violations


# ---------------------------------------------------------------------------
# Boundary Leak Detector Gate
# ---------------------------------------------------------------------------

SECRET_PATTERNS = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token shape", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("PyPI token shape", re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key shape", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OpenAI-style secret shape", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
)


def run_boundary_gate(target_path: Path, *, forbidden_terms: Sequence[str] = (),
                      check_secrets: bool = True,
                      ignored_parts: frozenset[str] = DEFAULT_IGNORED_PARTS) -> tuple[int, list[dict[str, Any]]]:
    patterns = [("forbidden_term_leak", "<redacted forbidden term pattern>", re.compile(re.escape(term), re.IGNORECASE))
                for term in forbidden_terms if term.strip()]
    if check_secrets:
        patterns.extend(("secret_leak", label, pattern) for label, pattern in SECRET_PATTERNS)
    violations: list[dict[str, Any]] = []
    used = [0, 0]
    scanned = 0

    def inspect_stream(stream: Any, location: str) -> None:
        nonlocal scanned
        content = _read_scan_stream(stream, used)
        scanned += 1
        for line_number, line in enumerate(content.splitlines(), 1):
            for kind, label, pattern in patterns:
                if pattern.search(line):
                    violations.append({"location": location, "line": line_number, "kind": kind, "label": label})

    for path in _scan_candidates(target_path, ignored_parts, violations):
        try:
            name = path.name.lower()
            if name.endswith(ARCHIVE_SUFFIXES):
                if path.stat().st_size > MAX_SCAN_TOTAL_BYTES:
                    raise ValueError("archive byte bound exceeded")
                if name.endswith((".zip", ".whl")):
                    with zipfile.ZipFile(path) as archive:
                        members = archive.infolist()
                        if len(members) > MAX_SCAN_FILES:
                            raise ValueError("archive entry bound exceeded")
                        for member in members:
                            if member.is_dir() or not _text_candidate(PurePosixPath(member.filename)):
                                continue
                            if member.file_size > MAX_SCAN_FILE_BYTES:
                                raise ValueError("archive member byte bound exceeded")
                            with archive.open(member) as stream:
                                inspect_stream(stream, path.name + ":" + member.filename)
                else:
                    with tarfile.open(path, "r:*") as archive:
                        declared_bytes = 0
                        for index, member in enumerate(archive):
                            if index >= MAX_SCAN_FILES:
                                raise ValueError("archive entry bound exceeded")
                            # Advancing a compressed tar decompresses even skipped binary members.
                            declared_bytes += member.size
                            if member.size > MAX_SCAN_FILE_BYTES or declared_bytes > MAX_SCAN_TOTAL_BYTES:
                                raise ValueError("archive expansion byte bound exceeded")
                            if not member.isfile():
                                if member.issym() or member.islnk():
                                    raise ValueError("archive link cannot establish retained target bytes")
                                continue
                            if not _text_candidate(PurePosixPath(member.name)):
                                continue
                            if member.size > MAX_SCAN_FILE_BYTES:
                                raise ValueError("archive member byte bound exceeded")
                            stream = archive.extractfile(member)
                            if stream is None:
                                raise ValueError("archive member unavailable")
                            with stream:
                                inspect_stream(stream, path.name + ":" + member.name)
            elif _text_candidate(path):
                with path.open("rb") as stream:
                    inspect_stream(stream, str(path))
        except (OSError, UnicodeError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile, tarfile.TarError) as exc:
            violations.append(_scan_error(str(path), type(exc).__name__ + ": selected input unavailable, malformed or beyond bounds"))
    if not scanned and not violations:
        violations.append(_scan_error(str(target_path), "no applicable text or archive members inspected"))
    return scanned, violations


# ---------------------------------------------------------------------------
# PR Description Gate
# ---------------------------------------------------------------------------

def run_pr_gate(
    body: str,
    *,
    commit: str | None = None,
    repo_root: Path | None = None,
) -> tuple[dict[str, Any], list[str]]:
    findings: list[str] = []
    if not body.strip():
        findings.append("PR description is empty")
        return {"status": "FAIL"}, findings

    if not re.search(r"(?i)(?:^|\n)\s*(?:#+\s*coordinate\b|coordinate\s*:)", body):
        findings.append("missing required Coordinate declaration in PR description")

    from verifier.domains.catalog import CHECKS
    # Check if number of domain adapters is stated and matches
    matches = re.finditer(r"\b(\w+)\s+(?:(?:executable|grounded|native)\s+)*domain\s+adapters\b", body, re.IGNORECASE)
    for match in matches:
        word = match.group(1).lower()
        NUMBER_WORDS = {
            "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
            "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
            "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
            "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
        }
        stated = int(word) if word.isdigit() else NUMBER_WORDS.get(word)
        if stated is not None and stated != len(CHECKS):
            findings.append(
                f"PR description states {word} domain adapters, but live catalogue has {len(CHECKS)}"
            )

    if commit is not None:
        if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            findings.append("commit must be a full lowercase Git object identifier")
        else:
            try:
                head = subprocess.run(["git", "-C", str(repo_root or Path.cwd()), "rev-parse", "HEAD"],
                                      capture_output=True, text=True, timeout=5, check=False)
                if head.returncode or head.stdout.strip() != commit:
                    findings.append("requested commit is not the readable repository HEAD")
            except (OSError, subprocess.TimeoutExpired):
                findings.append("repository HEAD could not be inspected within the deadline")
            if re.search(r"(?<![0-9a-f])" + re.escape(commit) + r"(?![0-9a-f])", body) is None:
                findings.append("description does not name the requested commit")
    report = {
        "status": "PASS" if not findings else "FAIL",
        "live_domain_count": len(CHECKS),
        "commit": commit,
        "claim_boundary": "Coordinate presence, stated native adapter counts and optional local HEAD binding only; substantive claims and review acceptance are not verified.",
    }
    return report, findings


# ---------------------------------------------------------------------------
# CI Pipeline Run Attestation Gate
# ---------------------------------------------------------------------------

def create_ci_attestation_receipt(
    *,
    workflow: str,
    run_id: str,
    run_number: str = "1",
    job: str = "conformance-gate",
    actor: str = "ci-runner",
    commit_sha: str = "0000000000000000000000000000000000000000",
    ref: str = "refs/heads/main",
    event_name: str = "push",
    status: str = "PASS",
    key: str | None = None,
) -> dict[str, Any]:
    """Record caller-supplied run metadata; this function executes no workflow."""
    if status not in ("PASS", "FAIL"):
        raise ValueError("attestation status must be PASS or FAIL")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    attestation_body = {
        "workflow": workflow,
        "run_id": str(run_id),
        "run_number": str(run_number),
        "job": job,
        "actor": actor,
        "commit_sha": commit_sha,
        "ref": ref,
        "event_name": event_name,
        "status": status,
        "timestamp": now,
    }

    body_bytes = canonical_bytes(attestation_body)
    attestation_digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()

    if key:
        signature = hmac.new(key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        signer_kind = "HMAC-SHA256"
    else:
        signature = hashlib.sha256(body_bytes).hexdigest()
        signer_kind = "CANONICAL-SHA256"

    receipt = {
        "schema_version": "verifier-ci-attestation-1",
        "receipt_id": f"ci:{run_id}:{job}",
        "attestation": attestation_body,
        "attestation_digest": attestation_digest,
        "signature": signature,
        "signer_kind": signer_kind,
        "status": status,
    }
    receipt["receipt_digest"] = "sha256:" + canonical_digest(receipt)
    return receipt


def verify_ci_attestation_receipt(
    receipt: dict[str, Any],
    *,
    key: str | None = None,
) -> tuple[bool, str]:
    if not isinstance(receipt, dict):
        return False, "receipt must be a dictionary"
    if set(receipt) != {"schema_version", "receipt_id", "attestation", "attestation_digest",
                        "signature", "signer_kind", "status", "receipt_digest"}:
        return False, "receipt fields differ from the exact contract"

    schema_ver = receipt.get("schema_version")
    if schema_ver != "verifier-ci-attestation-1":
        return False, f"unsupported schema_version: {schema_ver}"

    attestation_body = receipt.get("attestation")
    if not isinstance(attestation_body, dict):
        return False, "missing or invalid attestation body"
    fields = {"workflow", "run_id", "run_number", "job", "actor", "commit_sha", "ref", "event_name", "status", "timestamp"}
    if set(attestation_body) != fields or any(type(value) is not str or not value for value in attestation_body.values()):
        return False, "invalid attestation fields"
    if receipt["status"] != attestation_body["status"]:
        return False, "outer status differs from the recorded run status"

    body_bytes = canonical_bytes(attestation_body)
    expected_attestation_digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    if receipt.get("attestation_digest") != expected_attestation_digest:
        return False, "attestation_digest does not match canonical bytes of attestation"
    if receipt["receipt_id"] != f"ci:{attestation_body['run_id']}:{attestation_body['job']}":
        return False, "receipt identity differs from run and job"

    signer_kind = receipt.get("signer_kind")
    signature = receipt.get("signature")
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        return False, "signature must be 64 lowercase hexadecimal characters"
    if key is not None and signer_kind != "HMAC-SHA256":
        return False, "verification key requires HMAC-SHA256; unsigned downgrade rejected"
    if signer_kind == "HMAC-SHA256":
        if not key:
            return False, "receipt signed with HMAC-SHA256 requires verification key"
        expected_sig = hmac.new(key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature or "", expected_sig):
            return False, "HMAC-SHA256 signature verification failed"
    elif signer_kind == "CANONICAL-SHA256":
        expected_sig = hashlib.sha256(body_bytes).hexdigest()
        if signature != expected_sig:
            return False, "CANONICAL-SHA256 signature mismatch"
    else:
        return False, f"unsupported signer_kind: {signer_kind}"

    body_for_receipt = {k: v for k, v in receipt.items() if k != "receipt_digest"}
    expected_receipt_digest = "sha256:" + canonical_digest(body_for_receipt)
    if receipt.get("receipt_digest") != expected_receipt_digest:
        return False, "receipt_digest mismatch"

    status = receipt.get("status")
    if status != "PASS":
        return False, f"attestation status is {status}"

    return True, "valid"


# ---------------------------------------------------------------------------
# Parser and CLI Handlers
# ---------------------------------------------------------------------------

def add_gate_parsers(subparsers: Any) -> None:
    gate_parser = subparsers.add_parser(
        "gate",
        help="Plan and run bounded automation, scan selected inputs, and check retained receipts.",
    )
    sub = gate_parser.add_subparsers(dest="gate_subcommand", required=True)
    from verifier.runtime.gate_pipeline import add_pipeline_parsers
    add_pipeline_parsers(sub)

    # vstd gate pr
    pr_parser = sub.add_parser("pr", help="Check description coordinate/count metadata and optional local commit binding.")
    pr_parser.add_argument("--file", "-f", help="Path to pull-request description markdown file.")
    pr_parser.add_argument("--text", "-t", help="Raw pull-request description markdown text.")
    pr_parser.add_argument("--commit", "-c", help="Commit hash to verify against.")
    pr_parser.add_argument("--root", default=".", help="Repository root (default: current directory).")
    pr_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    # vstd gate paths
    paths_parser = sub.add_parser("paths", help="Scan for forbidden local absolute paths.")
    paths_parser.add_argument("target", nargs="?", default=".", help="Target directory or file to scan (default: current directory).")
    paths_parser.add_argument("--exclude", action="append", default=[], help="Glob pattern to exclude.")
    paths_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    # vstd gate ast
    ast_parser = sub.add_parser("ast", help="Detect selected loop/allocation source patterns; does not prove termination or enforce resource limits.")
    ast_parser.add_argument("target", nargs="?", default=".", help="Target directory or python file (default: current directory).")
    ast_parser.add_argument("--max-iterations", type=int, default=1000000, help="Maximum allowable loop bound (default: 1,000,000).")
    ast_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    # vstd gate boundary
    boundary_parser = sub.add_parser("boundary", help="Parameterized boundary leak detector.")
    boundary_parser.add_argument("target", nargs="?", default=".", help="Target file, directory, or archive to scan.")
    boundary_parser.add_argument("--forbidden", action="append", default=[], help="Forbidden terms/patterns to forbid.")
    boundary_parser.add_argument("--forbidden-file", help="File with forbidden terms (one per line).")
    boundary_parser.add_argument("--no-secrets", action="store_true", help="Disable secret token scanning.")
    boundary_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    # vstd gate attest
    attest_parser = sub.add_parser("attest", help="Record supplied run metadata with digest integrity or optional shared-key authentication; does not verify execution.")
    attest_parser.add_argument("--workflow", default=os.environ.get("GITHUB_WORKFLOW", "ci"), help="Workflow name.")
    attest_parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "1"), help="Pipeline run reference.")
    attest_parser.add_argument("--run-number", default=os.environ.get("GITHUB_RUN_NUMBER", "1"), help="Pipeline run number.")
    attest_parser.add_argument("--job", default=os.environ.get("GITHUB_JOB", "conformance-gate"), help="Pipeline job name.")
    attest_parser.add_argument("--actor", default=os.environ.get("GITHUB_ACTOR", "ci-runner"), help="Actor name.")
    attest_parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "0000000000000000000000000000000000000000"), help="Commit hash reference.")
    attest_parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", "refs/heads/main"), help="Git ref.")
    attest_parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME", "push"), help="Event name.")
    attest_parser.add_argument("--status", default="PASS", choices=["PASS", "FAIL"], help="Pipeline run outcome (default: PASS).")
    attest_parser.add_argument("--key", help="Optional secret key for HMAC-SHA256 signature.")
    attest_parser.add_argument("--key-env", help="Read the shared authentication key from this environment variable.")
    attest_parser.add_argument("--verify", help="Verify an existing continuous integration (CI) attestation receipt file.")
    attest_parser.add_argument("--output", "-o", help="File path to write receipt JSON.")
    attest_parser.add_argument("--json", action="store_true", help="Emit JSON output to stdout.")


def handle_gate_command(args: argparse.Namespace) -> int:
    sub = args.gate_subcommand
    if sub in {"init", "plan", "run", "check"}:
        from verifier.runtime.gate_pipeline import handle_pipeline_command
        return handle_pipeline_command(args)

    if sub == "pr":
        body = ""
        if args.file:
            path = Path(args.file)
            if not path.exists():
                print(f"[FAIL] PR description file not found: {path}", file=sys.stderr)
                return 1
            body = path.read_text(encoding="utf-8", errors="replace")
        elif args.text:
            body = args.text
        else:
            print("[FAIL] Either --file or --text required for vstd gate pr", file=sys.stderr)
            return 1

        report, findings = run_pr_gate(body, commit=args.commit, repo_root=Path(args.root))
        if args.json:
            print(json.dumps({"report": report, "findings": findings}, indent=2))
        else:
            if findings:
                print(f"[FAIL] PR description gate failed ({len(findings)} findings):")
                for f in findings:
                    print(f"  - {f}")
            else:
                print("[PASS] Selected description metadata checks passed; substantive claims are not verified.")
        return 0 if not findings else 1

    elif sub == "paths":
        target = Path(args.target).absolute()
        scanned, violations = run_paths_gate(target, additional_excludes=args.exclude)
        if args.json:
            print(json.dumps({
                "status": "PASS" if not violations else "FAIL",
                "scanned_files": scanned,
                "violations": violations,
            }, indent=2))
        else:
            if violations:
                print(f"[FAIL] Absolute paths detected in {len(violations)} locations:")
                for v in violations:
                    print(f"  - {v['file']}:{v['line']} [{v['label']}] {v['match']}")
            else:
                print(f"[PASS] Paths gate clean ({scanned} files scanned).")
        return 0 if not violations else 1

    elif sub == "ast":
        target = Path(args.target).absolute()
        scanned, violations = run_ast_gate(target, max_iterations=args.max_iterations)
        if args.json:
            print(json.dumps({
                "status": "PASS" if not violations else "FAIL",
                "scanned_files": scanned,
                "violations": violations,
            }, indent=2))
        else:
            if violations:
                print(f"[FAIL] AST gate detected {len(violations)} violations:")
                for v in violations:
                    print(f"  - {v['file']}:{v['line']} [{v['kind']}] {v['message']}")
            else:
                print(f"[PASS] AST gate clean ({scanned} python files scanned).")
        return 0 if not violations else 1

    elif sub == "boundary":
        target = Path(args.target).absolute()
        forbidden = list(args.forbidden or [])
        if args.forbidden_file:
            ff = Path(args.forbidden_file)
            try:
                for line in _read_scan_text(ff, [0, 0]).splitlines():
                    term = line.strip()
                    if term and not term.startswith("#"):
                        forbidden.append(term)
            except (OSError, UnicodeError, ValueError):
                error = {"status": "UNKNOWN", "reason": "forbidden terms file unavailable or beyond bounds"}
                print(json.dumps(error) if args.json else "[UNKNOWN] " + error["reason"])
                return 2
        scanned, violations = run_boundary_gate(
            target,
            forbidden_terms=forbidden,
            check_secrets=not args.no_secrets,
        )
        # The scanned path or archive member name may itself contain a secret.
        # Keep exact locations in the local API result, but never echo them to
        # command logs or machine-readable receipts.
        safe_violations = [
            {"finding_index": index, "line": int(v.get("line", 0)),
             "kind": v["kind"] if v.get("kind") in
             {"secret_leak", "forbidden_term_leak", "incomplete_scan"} else "other"}
            for index, v in enumerate(violations, 1)
        ]
        if args.json:
            print(json.dumps({
                "status": "PASS" if not violations else "FAIL",
                "scanned_targets": scanned,
                "violations": safe_violations,
            }, indent=2))
        else:
            if violations:
                print(f"[FAIL] Boundary gate detected {len(violations)} violations:")
                for v in safe_violations:
                    print(f"  - finding {v['finding_index']} line {v['line']} [{v['kind']}]")
            else:
                print(f"[PASS] Boundary gate clean ({scanned} items scanned).")
        return 0 if not violations else 1

    elif sub == "attest":
        if args.key_env:
            if args.key is not None or not os.environ.get(args.key_env):
                error = {"status": "UNKNOWN", "reason": "select one available authentication key source"}
                print(json.dumps(error) if args.json else "[UNKNOWN] " + error["reason"])
                return 2
            args.key = os.environ[args.key_env]
        if args.verify:
            verify_path = Path(args.verify)
            if not verify_path.exists():
                print(f"[FAIL] Receipt file not found: {verify_path}", file=sys.stderr)
                return 1
            try:
                receipt_data = strict_json_loads(_read_scan_text(verify_path, [0, 0]))
            except (OSError, ValueError, UnicodeError) as exc:
                print(f"[FAIL] Failed to parse receipt JSON: {exc}", file=sys.stderr)
                return 1
            is_valid, reason = verify_ci_attestation_receipt(receipt_data, key=args.key)
            if args.json:
                print(json.dumps({"valid": is_valid, "reason": reason, "receipt": receipt_data,
                                  "authenticated": is_valid and args.key is not None,
                                  "execution_verified": False}, indent=2))
            else:
                if is_valid:
                    print(f"[PASS] CI attestation receipt verified: {verify_path}")
                    print(f"       Receipt ID: {receipt_data.get('receipt_id')}")
                    print(f"       Signer:     {receipt_data.get('signer_kind')}")
                    print("       Scope: metadata integrity; workflow execution and actor identity are not verified.")
                else:
                    print(f"[FAIL] CI attestation receipt verification failed: {reason}", file=sys.stderr)
            return 0 if is_valid else 1

        receipt = create_ci_attestation_receipt(
            workflow=args.workflow,
            run_id=args.run_id,
            run_number=args.run_number,
            job=args.job,
            actor=args.actor,
            commit_sha=args.sha,
            ref=args.ref,
            event_name=args.event_name,
            status=args.status,
            key=args.key,
        )
        if args.output:
            out_p = Path(args.output).resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        if args.json or not args.output:
            print(json.dumps(receipt, indent=2))
        else:
            print(f"[PASS] CI attestation receipt written to {args.output}")
            print(f"       Receipt ID: {receipt['receipt_id']}")
            print(f"       Signature:  {receipt['signature']}")
        return 0

    return 1
