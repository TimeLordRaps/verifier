"""Terminology: abstract syntax tree (AST); Amazon Web Services (AWS);
application programming interface (API); command-line interface (CLI);
continuous integration (CI); directed acyclic graph (DAG); identifier (ID);
JavaScript Object Notation (JSON); line feed (LF);
pull request (PR); Pull Request Domain Explanation Language (PRDEL);
Python Package Index (PyPI);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource identifier (URI);
Unicode Transformation Format, 8-bit (UTF-8);
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
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    ".tex",
    ".json5",
    ".jsonc",
})

TEXT_BASENAMES = frozenset({
    "authors",
    "copying",
    "dockerfile",
    "license",
    "makefile",
    "notice",
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
    name_lower = path.name.lower()
    return (path.suffix.lower() in TEXT_SUFFIXES
            or name_lower in TEXT_BASENAMES
            or name_lower == ".env"
            or name_lower.startswith(".env."))


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
    if used[0] > MAX_SCAN_TOTAL_BYTES:
        raise ValueError("scan total byte bound exceeded")
    read_limit = min(MAX_SCAN_FILE_BYTES + 1, (MAX_SCAN_TOTAL_BYTES + 1) - used[0])
    data = stream.read(read_limit)
    used[0] += len(data)
    if len(data) > MAX_SCAN_FILE_BYTES:
        raise ValueError("scan byte bound exceeded")
    if used[0] > MAX_SCAN_TOTAL_BYTES:
        raise ValueError("scan total byte bound exceeded")
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


MAX_PRDEL_INPUT_BYTES = 64 * 1024 * 1024


class _PrdelReadLimit(ValueError):
    """Selected input cannot be read within its finite byte allocation."""


def _prdel_file(path: str, *, byte_limit: int | None = None) -> bytes:
    """Read bounded regular input without replacement decoding or link traversal."""
    if byte_limit is None:
        byte_limit = MAX_PRDEL_INPUT_BYTES
    if type(byte_limit) is not int or not 0 < byte_limit <= MAX_PRDEL_INPUT_BYTES:
        raise ValueError("positive bounded input allocation required")
    selected = Path(path)
    mode = selected.lstat()
    if selected.is_symlink() or not stat.S_ISREG(mode.st_mode):
        raise ValueError("input must be a regular file")
    if mode.st_size > byte_limit:
        raise _PrdelReadLimit("input exceeds the selected byte bound")
    with selected.open("rb") as stream:
        raw = stream.read(byte_limit + 1)
    if len(raw) > byte_limit:
        raise _PrdelReadLimit("input exceeds the selected byte bound")
    raw.decode("utf-8", errors="strict")
    return raw


# ---------------------------------------------------------------------------
# Parser and CLI Handlers
# ---------------------------------------------------------------------------

def _resolve_prdel_coordinates(
    args: argparse.Namespace, contract: str = "verifier-prdel-1"
) -> None:
    """Resolve explicit coordinates; retain unavailable selectors for diagnostics only.

    The shared engine always resolves again before a successful byte binding. Its
    diagnostic path retains known missing obligations when source is unavailable.
    """
    if not args.base or not args.commit:
        raise ValueError(
            f"{contract} requires explicit --base and --commit/--head"
        )
    from verifier.runtime.prdel import _revision, PrdelUnavailable

    resolved = []
    for selected in (args.base, args.commit):
        try:
            resolved.append(_revision(Path(args.root), selected))
        except PrdelUnavailable:
            resolved.append(selected)
    args.base, args.commit = resolved


def run_prdel_gate(
    body: str,
    *,
    commit: str,
    base: str,
    repo_root: Path | None = None,
    document: dict[str, Any] | None = None,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Versioned exact-source validation; host catalogue counts never qualify it.

    Successful bindings are recomputed from explicit local base/head by the shared
    engine. Known missing obligations retain FAIL when source remains unavailable.
    This bounded result does not establish execution, correctness or acceptance.
    """
    if not base or not commit:
        report = _prdel_input_error()
        report["findings"][0].update(
            code="PRDEL_COORDINATES_REQUIRED", category="PRDEL_COORDINATES_REQUIRED",
            reason="verifier-prdel-1 requires explicit nonempty base and head.",
            question="Select both review base and head, then rerun the bounded check.",
        )
        return report, [report["findings"][0]["reason"]]
    from verifier.runtime.prdel import (
        evaluate_description, _finalize, assertion_text, _revision, PrdelUnavailable,
    )

    root = repo_root or Path.cwd()
    report = evaluate_description(
        body, root, base, commit, document=document,
        requirements_bytes=requirements_bytes,
        expected_requirements_digest=expected_requirements_digest,
        evidence_bytes=evidence_bytes,
        expected_evidence_digest=expected_evidence_digest,
    )
    assertions = assertion_text(body, report)
    metadata = []
    if not body.strip():
        metadata.append("PR description is empty")
    if not re.search(r"(?i)(?:^|\n)\s*(?:#+\s*coordinate\b|coordinate\s*:)", assertions):
        metadata.append("missing required Coordinate declaration in PR description")
    exact = None
    try:
        exact = _revision(root, commit)
    except PrdelUnavailable:
        report["findings"].append({
            "code": "SOURCE_UNAVAILABLE", "category": "SOURCE_UNAVAILABLE", "status": "UNKNOWN",
            "reason": "Selected exact head could not be resolved within the shared bound.",
            "question": "Retain readable exact commit objects, then rerun validation.",
        })
    if exact is not None:
        if re.search(r"(?<![0-9a-f])" + re.escape(exact) + r"(?![0-9a-f])", assertions) is None:
            metadata.append("description does not name the selected exact head")
        named = re.findall(
            r"(?m)^Current (?:signed )?head:\s*`?([0-9a-f]{40}(?:[0-9a-f]{24})?)(?![0-9a-f])",
            assertions,
        )
        if any(value != exact for value in named):
            metadata.append("description names a head different from the selected exact commit")
    report["commit"] = exact
    report["metadata_findings"] = list(metadata)
    report["findings"] = list(report.get("findings", [])) + [
        {"code": "DESCRIPTION_METADATA_MISMATCH", "category": "DESCRIPTION_METADATA_MISMATCH",
         "status": "FAIL", "reason": row,
         "question": "Correct the selected description's coordinate/head metadata."}
        for row in metadata
    ]
    report = _finalize(report)
    return report, [str(row.get("reason") or row.get("question") or row.get("category"))
                    for row in report.get("findings", [])]


def run_prdel_gate_v2(
    body: str,
    *,
    commit: str,
    base: str,
    repo_root: Path | None = None,
    document: dict[str, Any] | None = None,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    replay_plan_bytes: bytes | None = None,
    expected_replay_plan_digest: str | None = None,
    limits: dict[str, int] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Run the explicitly selected source-bound version-two description gate."""
    if not base or not commit:
        report = _prdel_input_error("verifier-prdel-report-2")
        report["findings"][0].update(
            code="PRDEL_COORDINATES_REQUIRED",
            category="PRDEL_COORDINATES_REQUIRED",
            reason="verifier-prdel-2 requires explicit nonempty base and head.",
            question="Select both review base and head, then rerun the bounded check.",
        )
        return report, [report["findings"][0]["reason"]]
    from verifier.runtime.prdel import (
        evaluate_description_v2,
        _finalize,
        assertion_text,
        _revision,
        PrdelUnavailable,
    )

    root = repo_root or Path.cwd()
    report = evaluate_description_v2(
        body,
        root,
        base,
        commit,
        document=document,
        requirements_bytes=requirements_bytes,
        expected_requirements_digest=expected_requirements_digest,
        evidence_bytes=evidence_bytes,
        expected_evidence_digest=expected_evidence_digest,
        replay_plan_bytes=replay_plan_bytes,
        expected_replay_plan_digest=expected_replay_plan_digest,
        limits=limits,
    )
    assertions = assertion_text(body, report)
    metadata = []
    if not body.strip():
        metadata.append("PR description is empty")
    if not re.search(r"(?i)(?:^|\n)\s*(?:#+\s*coordinate\b|coordinate\s*:)", assertions):
        metadata.append("missing required Coordinate declaration in PR description")
    exact = None
    try:
        exact = _revision(root, commit)
    except PrdelUnavailable:
        report["findings"].append({
            "code": "SOURCE_UNAVAILABLE", "category": "SOURCE_UNAVAILABLE", "status": "UNKNOWN",
            "reason": "Selected exact head could not be resolved within the shared bound.",
            "question": "Retain readable exact commit objects, then rerun validation.",
        })
    if exact is not None:
        if re.search(r"(?<![0-9a-f])" + re.escape(exact) + r"(?![0-9a-f])", assertions) is None:
            metadata.append("description does not name the selected exact head")
        named = re.findall(
            r"(?m)^Current (?:signed )?head:\s*`?([0-9a-f]{40}(?:[0-9a-f]{24})?)(?![0-9a-f])",
            assertions,
        )
        if any(value != exact for value in named):
            metadata.append("description names a head different from the selected exact commit")
    report["commit"] = exact
    report["metadata_findings"] = list(metadata)
    report["findings"] = list(report.get("findings", [])) + [
        {"code": "DESCRIPTION_METADATA_MISMATCH", "category": "DESCRIPTION_METADATA_MISMATCH",
         "status": "FAIL", "reason": row,
         "question": "Correct the selected description's coordinate/head metadata."}
        for row in metadata
    ]
    report = _finalize(report)
    return report, [str(row.get("reason") or row.get("question") or row.get("category"))
                    for row in report.get("findings", [])]



def _prdel_input_error(
    report_schema: str = "verifier-prdel-report-1",
) -> dict[str, Any]:
    """Do not echo malformed input, private filenames, or exception payloads."""
    return {
        "schema_version": report_schema,
        "status": "FAIL",
        "source_grounding_status": "FAIL",
        "semantic_status": "FAIL",
        "verdict_scope": "GATE_OBLIGATION_FULFILLMENT",
        "proposition_truth": "NOT_INFERRED_FROM_MISSING_EVIDENCE",
        "required_checks_not_run": 0,
        ("claim_boundary"): (
            "Malformed, missing or conflicting selected input; no "
            "clearance established."
        ),
        "coverage": {},
        "findings": [
            {
                "code": "INVALID_INPUT",
                "category": "INVALID_INPUT",
                "status": "FAIL",
                "reason": "Selected input is unavailable, malformed or beyond bounds.",
                ("question"): (
                    "Provide bounded UTF-8 inputs, valid JSON and "
                    "resolvable exact Git revisions."
                ),
            }
        ],
    }



def _prdel_emit(value: Any, args: argparse.Namespace) -> None:
    rendered = (
        value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True)
    )
    if args.output:
        with Path(args.output).open("w", encoding="utf-8", newline="\n") as destination:
            destination.write(rendered.rstrip("\n") + "\n")
    else:
        print(rendered)



def _compare_prdel_documents(
    args: argparse.Namespace, requirements: bytes | None
) -> dict[str, Any]:
    """Recompute selected branch graphs; carried graphs cannot establish coverage."""
    from verifier.runtime.prdel import generate_prdel, PrdelUnavailable
    from verifier.runtime.prdel_coverage import preventative_obligations

    try:
        current = generate_prdel(
            Path(args.root),
            args.base,
            args.commit,
            requirements,
            args.requirements_digest,
        )
    except PrdelUnavailable:
        return {
            "schema_version": "verifier-prdel-preventative-1",
            "verdict": "UNKNOWN",
            "notices": [],
            "findings": [
                {
                    "code": "COMPARISON_SOURCE_UNAVAILABLE",
                    "verdict": "UNKNOWN",
                    ("question"): (
                        "Retain exact current source objects before "
                        "comparing pinned branch graphs."
                    ),
                }
            ],
            "delivery": "NOT_SENT",
            "source_binding": None,
            "compared_bindings": [],
            "selected_document_count": len(args.compare_document),
            "bounds": {"complete": False},
        }
    graphs: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    if len(args.compare_document) > 32:
        failures.append(
            {
                "code": "COMPARISON_BOUND_EXCEEDED",
                "verdict": "UNKNOWN",
                ("question"): (
                    "Select at most 32 pinned comparison documents; "
                    "unexamined selections remain unresolved."
                ),
            }
        )
    for index, path in enumerate(args.compare_document[:32]):
        try:
            document = strict_json_loads(_prdel_file(path).decode("utf-8"))
            if type(document) is not dict or type(document.get("binding")) is not dict:
                raise ValueError("comparison document is not bound")
            binding = document["binding"]
            if any(
                type(binding.get(key)) is not str
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", binding[key])
                for key in ("base", "head")
            ):
                raise ValueError("comparison revisions are not exact")
            expected = generate_prdel(
                Path(args.root),
                binding["base"],
                binding["head"],
                requirements,
                args.requirements_digest,
            )
            if any(
                document.get(key) != expected[key]
                for key in (
                    "binding",
                    "requirements",
                    "source_obligations",
                    "impact_graph",
                )
            ):
                failures.append(
                    {
                        "code": "STALE_OR_SUBSTITUTED_COMPARISON",
                        "verdict": "FAIL",
                        "document_index": index,
                        ("question"): (
                            "Regenerate the selected comparison "
                            "document using exact source and the "
                            "same explicitly selected requirements."
                        ),
                    }
                )
                continue
            graphs.append(expected["impact_graph"])
        except PrdelUnavailable:
            failures.append(
                {
                    "code": "COMPARISON_SOURCE_UNAVAILABLE",
                    "verdict": "UNKNOWN",
                    "document_index": index,
                    ("question"): (
                        "Retain the comparison's exact commit "
                        "objects and rerun; unavailable source is "
                        "not a disproved contract."
                    ),
                }
            )
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
            failures.append(
                {
                    "code": "INVALID_COMPARISON_INPUT",
                    "verdict": "FAIL",
                    "document_index": index,
                    ("question"): (
                        "Supply a bounded valid PRDEL document with "
                        "exact revisions and recomputable graph "
                        "bindings."
                    ),
                }
            )
    report = preventative_obligations(current["impact_graph"], graphs)
    report["findings"].extend(failures)
    report["source_binding"] = current["binding"]
    report["compared_bindings"] = [graph["binding"] for graph in graphs]
    report["selected_document_count"] = len(args.compare_document)
    if failures:
        report["verdict"] = (
            "FAIL"
            if any(row["verdict"] == "FAIL" for row in report["findings"])
            else "UNKNOWN"
        )
    return report





def _has_shard_selectors(args: argparse.Namespace) -> bool:
    return any(getattr(args, name, None) is not None for name in (
        "manifest", "manifest_digest", "source_digest", "compilation_residuals", "packet_budget_bytes"
    )) or any(bool(getattr(args, name, None)) for name in ("shard", "shard_digest"))


def _handle_prdel_shard_command(args: argparse.Namespace) -> int:
    """Opt-in selected artifact admission; tool rendering never grants clearance."""
    from verifier.runtime import prdel, prdel_rules, prdel_shards
    report = None
    rendered_body = None
    operation = "render" if args.render else "validate"
    try:
        if getattr(args, "contract", None) != "verifier-prdel-shard-description-1":
            raise ValueError("Shard selectors require the explicit sharded description contract.")
        if any(bool(getattr(args, name, None)) for name in (
            "generate", "template", "compilation", "document", "impact_dag", "compare_document"
        )):
            raise ValueError("Selected shard rendering or validation required; compilation produces separately retained artifacts.")
        if not all((args.manifest, args.manifest_digest, args.source_digest,
                    args.compilation_residuals, args.shard, args.shard_digest)):
            raise ValueError("Explicit manifest, ordered shards, source and residual selection required.")
        if len(args.shard) != len(args.shard_digest) or len(args.shard) > prdel.MAX_REGIONS * 4:
            raise ValueError("Each finite selected shard requires its own ordered digest.")
        if type(args.packet_budget_bytes) is not int or not 0 < args.packet_budget_bytes <= prdel.MAX_SNAPSHOT_BYTES:
            raise ValueError("Explicit supported caller packet budget required.")
        if bool(args.requirements) != bool(args.requirements_digest) or bool(args.evidence) != bool(args.evidence_digest):
            raise ValueError("Selected requirements/evidence must have their expected digests.")
        if args.file and args.text is not None:
            raise ValueError("Choose one complete description input.")
        if args.render and (args.file or args.text is not None):
            raise ValueError("Rendering produces the selected canonical description.")
        if not args.render and not args.file and args.text is None:
            raise ValueError("Validation requires the complete selected description.")
        _resolve_prdel_coordinates(args)
        artifact_limit = min(prdel_rules.MAX_COMPILED_BYTES, prdel.MAX_DOCUMENT_BYTES)
        manifest_limit = min(artifact_limit, args.packet_budget_bytes)
        try:
            manifest = _prdel_file(args.manifest, byte_limit=manifest_limit)
        except _PrdelReadLimit:
            if manifest_limit < artifact_limit:
                raise prdel.PrdelUnavailable("Selected packet budget exhausted.")
            raise
        total = len(manifest)
        shards = []
        for path in args.shard:
            # Read at most the remaining selected budget plus one sentinel byte.
            remaining = args.packet_budget_bytes - total
            if remaining <= 0:
                raise prdel.PrdelUnavailable("Selected packet budget exhausted.")
            selected_limit = min(artifact_limit, remaining)
            try:
                raw = _prdel_file(path, byte_limit=selected_limit)
            except _PrdelReadLimit:
                if selected_limit < artifact_limit:
                    raise prdel.PrdelUnavailable("Selected packet budget exhausted.")
                raise
            total += len(raw)
            shards.append(raw)
        requirements = _prdel_file(args.requirements) if args.requirements else None
        evidence = _prdel_file(args.evidence) if args.evidence else None
        residuals = strict_json_loads(_prdel_file(args.compilation_residuals).decode("utf-8"))
        definitions = None
        if args.definition:
            from verifier.runtime.explanation_projection import load_definitions
            definitions = load_definitions(_prdel_file(args.definition))
        _, requirements_digest = prdel._requirements(requirements, args.requirements_digest)
        selection = {"expected_manifest_digest": args.manifest_digest,
            "expected_shard_digests": args.shard_digest, "expected_source_digest": args.source_digest,
            "requirements_digest": requirements_digest, "expected_required_residuals": residuals,
            "packet_budget_bytes": args.packet_budget_bytes, "requirements_bytes": requirements,
            "evidence_bytes": evidence, "expected_evidence_digest": args.evidence_digest,
            "definition": definitions}
        if args.render:
            rendered = prdel_shards.render_prdel_shard_description(manifest, shards, Path(args.root), args.base, args.commit, **selection)
            report, rendered_body = rendered["report"], rendered["body"]
        else:
            body = _prdel_file(args.file, byte_limit=prdel_shards.SHARD_HUMAN_BODY_BYTES).decode("utf-8") if args.file else args.text
            report = prdel_shards.evaluate_prdel_shard_description(body, manifest, shards, Path(args.root), args.base, args.commit, **selection)
    except FileNotFoundError:
        report = prdel_shards._shard_gate_error("FAIL", "A selected required input is confirmed missing.")
    except (prdel.PrdelUnavailable, OSError):
        report = prdel_shards._shard_gate_error("UNKNOWN", "Selected input or complete output is unavailable within its budget.")
    except (prdel.PrdelError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        report = prdel_shards._shard_gate_error("FAIL", "Selected shard input is malformed, incomplete, conflicting or outside its declared profile.")
    envelope = {"schema_version": "verifier-prdel-shard-cli-1", "operation": operation,
        "status": report["status"], "body": rendered_body, "report": report}
    try:
        _prdel_emit(envelope if args.json or not args.render or rendered_body is None else rendered_body, args)
    except (OSError, UnicodeError, ValueError):
        envelope["body"] = None
        if report["status"] != "FAIL":
            report["status"] = envelope["status"] = "UNKNOWN"
        report["required_replay_findings"].append({"code": "SHARDED_OUTPUT_UNAVAILABLE", "status": "UNKNOWN",
            "reason": "Complete selected output could not be written."})
        print(json.dumps(envelope, sort_keys=True))
        return 1 if report["status"] == "FAIL" else 2
    if args.render and rendered_body is not None:
        return 0
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[report["status"]]


def _prdel_v2_capability_report(reason: str) -> dict[str, Any]:
    report = _prdel_input_error("verifier-prdel-report-2")
    report["status"] = "UNKNOWN"
    report["source_grounding_status"] = "UNKNOWN"
    report["semantic_status"] = "UNKNOWN"
    report["required_checks_not_run"] = 1
    report["claim_boundary"] = (
        "The selected version-two capability is not implemented; no version-one "
        "fallback, source clearance or proposition verdict is inferred."
    )
    report["findings"][0].update(
        code="PRDEL_V2_CAPABILITY_UNAVAILABLE",
        category="PRDEL_V2_CAPABILITY_UNAVAILABLE",
        status="UNKNOWN",
        reason=reason,
        question=(
            "Use the explicit version-two manual template/validation route or "
            "implement and qualify a separately versioned capability."
        ),
    )
    return report


def _has_prdel_v2_shard_selectors(args: argparse.Namespace) -> bool:
    return any(
        getattr(args, name, None) is not None
        for name in (
            "manifest",
            "manifest_digest",
            "source_digest",
            "packet_budget_bytes",
        )
    ) or any(bool(getattr(args, name, None)) for name in ("shard", "shard_digest"))


def _prdel_v2_cli_logical_report(
    shard_report: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Retain the shard result while exposing the stable CLI report shape."""
    selected_status = shard_report.get("status")
    status = selected_status if selected_status in {"PASS", "FAIL", "UNKNOWN"} else "UNKNOWN"
    logical = shard_report.get("logical_report")
    report = (
        dict(logical)
        if type(logical) is dict
        and logical.get("schema_version") == "verifier-prdel-report-2"
        else _prdel_input_error("verifier-prdel-report-2")
    )
    report["schema_version"] = "verifier-prdel-report-2"
    report["status"] = status
    for field in ("source_grounding_status", "semantic_status"):
        current = report.get(field)
        if current not in {"PASS", "FAIL", "UNKNOWN"}:
            report[field] = status
    report.setdefault("verdict_scope", "GATE_OBLIGATION_FULFILLMENT")
    report.setdefault("proposition_truth", "NOT_INFERRED_FROM_MISSING_EVIDENCE")
    report.setdefault("required_checks_not_run", 1 if status == "UNKNOWN" else 0)
    report.setdefault(
        "claim_boundary",
        (
            "The selected private version-two packet was checked only for bounded "
            "transport, exact recomposition, and the existing logical gate. No "
            "release, correctness, or proposition-truth claim is inferred."
        ),
    )
    reason = shard_report.get("reason")
    findings = report.get("findings")
    if type(findings) is not list or not findings:
        reason_text = (
            reason
            if type(reason) is str and reason
            else "Selected version-two shard validation completed with no detailed finding."
        )
        report["findings"] = [
            {
                "code": "PRDEL_V2_SHARD_" + status,
                "category": "PRDEL_V2_SHARD_" + status,
                "status": status,
                "reason": reason_text,
                "question": (
                    "Retain the complete selected packet and exact source, then rerun "
                    "the bounded version-two shard validation."
                ),
            }
        ]
    finding_text = [
        str(row.get("reason") or row.get("question") or row.get("category"))
        for row in report["findings"]
        if type(row) is dict
    ]
    return report, finding_text


def _prdel_v2_missing_selection(reason: str) -> tuple[dict[str, Any], list[str]]:
    report = _prdel_input_error("verifier-prdel-report-2")
    report["status"] = "UNKNOWN"
    report["source_grounding_status"] = "UNKNOWN"
    report["semantic_status"] = "UNKNOWN"
    report["required_checks_not_run"] = 1
    report["claim_boundary"] = (
        "A required explicit version-two input was not selected; no validation, "
        "clearance, proposition verdict, or version-one fallback is inferred."
    )
    report["findings"][0].update(
        code="PRDEL_V2_CAPABILITY_UNAVAILABLE",
        category="PRDEL_V2_CAPABILITY_UNAVAILABLE",
        status="UNKNOWN",
        reason=reason,
        question="Select every required bounded input and rerun the version-two operation.",
    )
    return report, [reason]


def _validate_prdel_v2_shard_selection(
    args: argparse.Namespace,
    requirements: bytes | None,
    evidence: bytes | None,
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    """Read one explicitly selected bounded packet and use the existing validator."""
    from verifier.runtime import prdel, prdel_v2_shards

    def finish(
        shard_report: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        logical_report, findings = _prdel_v2_cli_logical_report(shard_report)
        return logical_report, findings, shard_report

    missing = [
        name
        for name, value in (
            ("manifest", args.manifest),
            ("manifest digest", args.manifest_digest),
            ("source digest", args.source_digest),
            ("packet budget", args.packet_budget_bytes),
        )
        if value is None
    ]
    if missing or len(args.shard) != len(args.shard_digest):
        reason = (
            "The complete ordered version-two manifest, shard, digest, source, and "
            "packet-budget selection is unavailable."
        )
        shard_report = prdel_v2_shards._report("UNKNOWN", "UNKNOWN", reason)
        report, findings, shard_report = finish(shard_report)
        report["findings"][0].update(
            code="PRDEL_V2_CAPABILITY_UNAVAILABLE",
            category="PRDEL_V2_CAPABILITY_UNAVAILABLE",
            reason=reason,
        )
        return report, findings, shard_report
    if len(args.shard) > prdel.MAX_REGIONS * 4:
        return finish(
            prdel_v2_shards._report(
                "FAIL", "FAIL", "Selected shard count exceeds the finite profile."
            )
        )
    selected_digests = [args.manifest_digest, args.source_digest, *args.shard_digest]
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in selected_digests
    ):
        return finish(
            prdel_v2_shards._report(
                "FAIL", "FAIL", "Every external packet digest must be exact lowercase SHA-256."
            )
        )
    if (
        type(args.packet_budget_bytes) is not int
        or isinstance(args.packet_budget_bytes, bool)
        or not 0 < args.packet_budget_bytes <= prdel.MAX_DESCRIPTION_BYTES
    ):
        return finish(
            prdel_v2_shards._report(
                "FAIL", "FAIL", "Selected packet budget is outside the supported profile."
            )
        )

    try:
        artifact_limit = min(prdel.MAX_DOCUMENT_BYTES, args.packet_budget_bytes)
        manifest_bytes = _prdel_file(args.manifest, byte_limit=artifact_limit)
        total = len(manifest_bytes)
        shard_bytes: list[bytes] = []
        for selected_path in args.shard:
            remaining = args.packet_budget_bytes - total
            if remaining <= 0:
                raise prdel.PrdelUnavailable("Selected packet budget exhausted.")
            raw = _prdel_file(
                selected_path,
                byte_limit=min(prdel.MAX_DOCUMENT_BYTES, remaining),
            )
            total += len(raw)
            shard_bytes.append(raw)
        if prdel.digest(manifest_bytes) != args.manifest_digest:
            raise prdel.PrdelError("selected manifest digest differs")
        if any(
            prdel.digest(raw) != expected
            for raw, expected in zip(shard_bytes, args.shard_digest)
        ):
            raise prdel.PrdelError("selected shard digest differs")
        manifest = prdel.decode(manifest_bytes)
        binding = manifest.get("document_header", {}).get("binding", {})
        if (
            type(binding) is not dict
            or binding.get("source_digest") != args.source_digest
        ):
            raise prdel.PrdelError("selected source digest differs from packet binding")
        return finish(
            prdel_v2_shards.validate_prdel_v2_shards(
                manifest_bytes,
                shard_bytes,
                Path(args.root),
                args.base,
                args.commit,
                requirements_bytes=requirements,
                expected_requirements_digest=args.requirements_digest,
                evidence_bytes=evidence,
                expected_evidence_digest=args.evidence_digest,
            )
        )
    except (_PrdelReadLimit, prdel.PrdelUnavailable, OSError):
        return finish(
            prdel_v2_shards._report(
                "UNKNOWN",
                "UNKNOWN",
                "Selected packet input is unavailable within the declared byte budget.",
            )
        )
    except (
        prdel.PrdelError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        OverflowError,
    ):
        return finish(
            prdel_v2_shards._report(
                "FAIL",
                "FAIL",
                "Selected packet is malformed, reordered, substituted, or cross-bound.",
            )
        )


def _emit_prdel_v2_report(
    args: argparse.Namespace,
    report: dict[str, Any],
    findings: list[str],
    *,
    allow_output: bool = True,
    operation: str | None = None,
    rendered: str | None = None,
    shard_report: dict[str, Any] | None = None,
) -> int:
    envelope = {
        "schema_version": "verifier-prdel-cli-2",
        "status": report["status"],
        "report": report,
        "findings": findings,
    }
    if operation is not None:
        envelope["operation"] = operation
    if rendered is not None:
        envelope["rendered"] = rendered
    if shard_report is not None:
        envelope["shard_report"] = shard_report
    if operation == "render" and rendered is not None and not args.json and allow_output:
        if args.output:
            _prdel_emit(rendered, args)
        else:
            sys.stdout.write(rendered)
    elif (args.json or args.output) and allow_output:
        _prdel_emit(envelope, args)
    elif args.json or args.output:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        print(f"[{report['status']}] PRDEL v2 exact-source description gate")
        for finding in report.get("findings", []):
            print(
                "  - "
                + str(finding.get("category", "UNRESOLVED"))
                + ": "
                + str(finding.get("reason", ""))
            )
        print("Boundary: " + report["claim_boundary"])
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(report["status"], 2)


def _prdel_v2_graph_limits(
    args: argparse.Namespace, *, require_explicit: bool = False
) -> dict[str, int]:
    """Return one capped selection used identically by generation and validation."""
    defaults = {
        "max_nodes": 10000,
        "max_edges": 20000,
        "max_operations": 200000,
        "max_output_bytes": 8 * 1024 * 1024,
    }
    caps = {
        "max_nodes": 200000,
        "max_edges": 400000,
        "max_operations": 50000000,
        "max_output_bytes": 32 * 1024 * 1024,
    }
    selected: dict[str, int] = {}
    supplied = {
        key: getattr(args, "prdel_" + key, None) for key in defaults
    }
    if (require_explicit or any(value is not None for value in supplied.values())) and any(
        value is None for value in supplied.values()
    ):
        raise ValueError("all four PRDEL graph limits must be selected together")
    for key, default in defaults.items():
        value = supplied[key]
        value = default if value is None else value
        if type(value) is not int or not 1 <= value <= caps[key]:
            raise ValueError("selected PRDEL graph limit is outside its fixed cap")
        selected[key] = value
    return selected


def _handle_prdel_v2_command(args: argparse.Namespace) -> int:
    """Expose qualified v2 generation, render equality, validation and shard replay."""
    report = None
    try:
        if bool(args.requirements) != bool(args.requirements_digest):
            raise ValueError("requirements and their expected digest must be selected together")
        if bool(args.evidence) != bool(args.evidence_digest):
            raise ValueError("evidence and their expected digest must be selected together")
        if bool(getattr(args, "replay_plan", None)) != bool(
            getattr(args, "replay_plan_digest", None)
        ):
            raise ValueError(
                "replay plan and its expected digest must be selected together"
            )
        limits = _prdel_v2_graph_limits(
            args, require_explicit=bool(getattr(args, "replay_plan", None))
        )
        _resolve_prdel_coordinates(args, "verifier-prdel-2")
        from verifier.runtime.prdel import (
            generate_prdel_v2,
            render_prdel_v2,
            PrdelUnavailable,
            _finalize,
        )

        has_v2_shards = _has_prdel_v2_shard_selectors(args)
        unsupported = []
        if not args.generate and args.template:
            raise ValueError("authoring selectors require generation")
        if args.generate and not args.template:
            unsupported.append("version-two compilation is not implemented")
        if args.compilation or args.definition or args.compilation_residuals:
            unsupported.append("version-two rule compilation and definitions are not implemented")
        if args.compare_document:
            unsupported.append("version-two preventative comparison is not implemented")
        if args.impact_dag:
            unsupported.append("version-two impact-DAG tool operations are not implemented")
        if unsupported:
            report = _prdel_v2_capability_report("; ".join(sorted(set(unsupported))))
            return _emit_prdel_v2_report(
                args, report, [report["findings"][0]["reason"]]
            )

        if args.file and args.text is not None:
            raise ValueError("choose one description input")
        if args.render and has_v2_shards:
            raise ValueError("rendering and shard validation are separate operations")
        requirements = _prdel_file(args.requirements) if args.requirements else None
        evidence = _prdel_file(args.evidence) if args.evidence else None
        replay_plan = (
            _prdel_file(
                args.replay_plan,
                byte_limit=2 * 1024 * 1024,
            )
            if getattr(args, "replay_plan", None)
            else None
        )

        if has_v2_shards:
            if replay_plan is not None or any(
                getattr(args, name, None) is not None
                for name in (
                    "prdel_max_nodes",
                    "prdel_max_edges",
                    "prdel_max_operations",
                    "prdel_max_output_bytes",
                )
            ):
                raise ValueError(
                    "replay and graph-limit selectors do not apply to shard admission"
                )
            if any(
                (
                    args.generate,
                    args.template,
                    args.file,
                    args.text is not None,
                    args.document,
                    args.render,
                )
            ):
                raise ValueError("shard validation cannot consume another v2 operation")
            report, findings, shard_report = _validate_prdel_v2_shard_selection(
                args, requirements, evidence
            )
            return _emit_prdel_v2_report(
                args,
                report,
                findings,
                operation="validate-shards",
                shard_report=shard_report,
            )

        document = (
            strict_json_loads(_prdel_file(args.document).decode("utf-8"))
            if args.document
            else None
        )
        if document is not None and type(document) is not dict:
            raise ValueError("document must be an object")
        if document is not None and str(document.get("schema_version", "")).startswith(
            "verifier-prdel-compilation-"
        ):
            report = _prdel_v2_capability_report(
                "version-two compilation envelopes are not implemented"
            )
            return _emit_prdel_v2_report(
                args, report, [report["findings"][0]["reason"]]
            )

        if args.generate:
            if (
                args.file
                or args.text is not None
                or args.document
                or args.evidence
                or args.evidence_digest
                or replay_plan is not None
                or args.render
            ):
                raise ValueError(
                    "generation cannot consume description, document rendering, or execution evidence"
                )
            try:
                template = generate_prdel_v2(
                    Path(args.root),
                    args.base,
                    args.commit,
                    requirements_bytes=requirements,
                    expected_requirements_digest=args.requirements_digest,
                    limits=limits,
                )
            except PrdelUnavailable:
                report = _prdel_v2_capability_report(
                    "Exact selected source is unavailable or generation exceeded a declared bound."
                )
                report["findings"][0].update(
                    code="SOURCE_UNAVAILABLE", category="SOURCE_UNAVAILABLE"
                )
                return _emit_prdel_v2_report(
                    args, report, [report["findings"][0]["reason"]]
                )
            _prdel_emit(template, args)
            return 0

        if args.render and document is None:
            report, findings = _prdel_v2_missing_selection(
                "An explicit version-two document was not selected for rendering."
            )
            return _emit_prdel_v2_report(args, report, findings)
        if args.render:
            if args.file or args.text is not None:
                raise ValueError("rendering accepts only the explicit selected document")
            rendered = render_prdel_v2(document)
            report, findings = run_prdel_gate_v2(
                rendered,
                commit=args.commit,
                repo_root=Path(args.root),
                base=args.base,
                document=document,
                requirements_bytes=requirements,
                expected_requirements_digest=args.requirements_digest,
                evidence_bytes=evidence,
                expected_evidence_digest=args.evidence_digest,
                replay_plan_bytes=replay_plan,
                expected_replay_plan_digest=getattr(
                    args, "replay_plan_digest", None
                ),
                limits=limits,
            )
            return _emit_prdel_v2_report(
                args,
                report,
                findings,
                operation="render",
                rendered=rendered,
            )

        body = _prdel_file(args.file).decode("utf-8") if args.file else args.text
        if body is None and document is not None:
            body = render_prdel_v2(document)
        if body is None:
            raise ValueError("validation requires a description or document")
        report, findings = run_prdel_gate_v2(
            body,
            commit=args.commit,
            repo_root=Path(args.root),
            base=args.base,
            document=document,
            requirements_bytes=requirements,
            expected_requirements_digest=args.requirements_digest,
            evidence_bytes=evidence,
            expected_evidence_digest=args.evidence_digest,
            replay_plan_bytes=replay_plan,
            expected_replay_plan_digest=getattr(args, "replay_plan_digest", None),
            limits=limits,
        )
        return _emit_prdel_v2_report(args, report, findings)
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        ImportError,
        SyntaxError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        assessed = report
        report = _prdel_input_error("verifier-prdel-report-2")
        if isinstance(
            error, (OSError, ImportError, subprocess.SubprocessError)
        ) and not isinstance(error, FileNotFoundError):
            report["status"] = "UNKNOWN"
            report["source_grounding_status"] = "UNKNOWN"
            report["semantic_status"] = "UNKNOWN"
            report["findings"][0].update(
                code="UNAVAILABLE_INPUT",
                category="UNAVAILABLE_INPUT",
                status="UNKNOWN",
                reason="Selected input or trusted tooling is unavailable.",
            )
            if assessed is not None:
                assessed["findings"] = list(assessed["findings"]) + report["findings"]
                report = _finalize(assessed)
        return _emit_prdel_v2_report(
            args,
            report,
            [report["findings"][0]["reason"]],
            allow_output=False,
        )


def _handle_prdel_command(args: argparse.Namespace) -> int:
    """Generate/render are tool operations; only validation can grant clearance."""
    if getattr(args, "contract", None) == "verifier-prdel-2":
        return _handle_prdel_v2_command(args)
    if _has_shard_selectors(args) or getattr(args, "contract", None) == "verifier-prdel-shard-description-1":
        return _handle_prdel_shard_command(args)
    report = None
    compilation_report = None
    try:
        if any(
            getattr(args, name, None) is not None
            for name in (
                "replay_plan",
                "replay_plan_digest",
                "prdel_max_nodes",
                "prdel_max_edges",
                "prdel_max_operations",
                "prdel_max_output_bytes",
            )
        ):
            raise ValueError("replay and graph-limit selectors require verifier-prdel-2")
        if bool(args.requirements) != bool(args.requirements_digest):
            raise ValueError('requirements and their expected digest must be selected together')
        if bool(args.evidence) != bool(args.evidence_digest):
            raise ValueError('evidence and its expected digest must be selected together')
        _resolve_prdel_coordinates(args)
        from verifier.runtime.prdel import (
            generate_prdel,
            render_prdel,
            render_impact_mermaid,
            PrdelUnavailable,
            _finalize,
        )

        if (
            sum(bool(value) for value in (args.generate, args.render, args.impact_dag))
            > 1
        ):
            raise ValueError("choose one tool operation")
        if args.file and args.text is not None:
            raise ValueError("choose one description input")
        if (args.template or args.compilation) and not args.generate:
            raise ValueError("authoring selectors require generation")
        if args.template and (args.compilation or args.definition):
            raise ValueError("manual template cannot select compilation or definitions")
        requirements = _prdel_file(args.requirements) if args.requirements else None
        evidence = _prdel_file(args.evidence) if args.evidence else None
        document = (
            strict_json_loads(_prdel_file(args.document).decode("utf-8"))
            if args.document
            else None
        )
        if document is not None and type(document) is not dict:
            raise ValueError("document must be an object")
        if not args.generate:
            if (
                document is not None
                and document.get("schema_version") == "verifier-prdel-compilation-1"
            ):
                from verifier.runtime.prdel_rules import validate_compilation
                from verifier.runtime.explanation_projection import load_definitions

                definitions = (
                    load_definitions(_prdel_file(args.definition))
                    if args.definition
                    else None
                )
                compilation_report = validate_compilation(
                    document,
                    Path(args.root),
                    args.base,
                    args.commit,
                    requirements,
                    args.requirements_digest,
                    definitions,
                )
                document = document.get("document")
                if type(document) is not dict:
                    raise ValueError("compilation has no bound source document")
            elif args.definition:
                raise ValueError(
                    "selected definition validation requires a compilation envelope"
                )
        if args.generate:
            if (
                args.file
                or args.text is not None
                or args.document
                or args.evidence
                or args.evidence_digest
                or args.compare_document
            ):
                raise ValueError(
                    "generation cannot consume description or execution evidence"
                )
            try:
                if args.template:
                    template = generate_prdel(
                        Path(args.root),
                        args.base,
                        args.commit,
                        requirements_bytes=requirements,
                        expected_requirements_digest=args.requirements_digest,
                    )
                else:
                    from verifier.runtime.prdel_rules import compile_prdel
                    from verifier.runtime.explanation_projection import load_definitions

                    definitions = (
                        load_definitions(_prdel_file(args.definition))
                        if args.definition
                        else None
                    )
                    compiled = compile_prdel(
                        Path(args.root),
                        args.base,
                        args.commit,
                        requirements_bytes=requirements,
                        expected_requirements_digest=args.requirements_digest,
                        definition=definitions,
                    )
                    if compiled["document"] is None:
                        _prdel_emit(compiled, args)
                        return {"FAIL": 1, "UNKNOWN": 2}.get(compiled["status"], 2)
                    template = compiled if args.compilation else compiled["document"]
            except PrdelUnavailable:
                report = _prdel_input_error()
                report["status"] = report["source_grounding_status"] = report[
                    "semantic_status"
                ] = "UNKNOWN"
                report["findings"][0].update(
                    code="SOURCE_UNAVAILABLE",
                    category="SOURCE_UNAVAILABLE",
                    status="UNKNOWN",
                    reason=(
                        "Exact selected source is unavailable or "
                        "generation exceeds declared byte/time "
                        "bounds."
                    ),
                    question=(
                        "Retain the selected objects or split the "
                        "review into bounded changes, then retry "
                        "generation."
                    ),
                )
                _prdel_emit(
                    {
                        "schema_version": "verifier-prdel-cli-1",
                        "status": "UNKNOWN",
                        "report": report,
                        "findings": [report["findings"][0]["reason"]],
                    },
                    args,
                )
                return 2
            _prdel_emit(template, args)
            return 0
        body = _prdel_file(args.file).decode("utf-8") if args.file else args.text
        if body is None and document is not None:
            body = render_prdel(document)
        if body is None:
            raise ValueError("validation requires a description or document")
        report, findings = run_prdel_gate(
            body,
            commit=args.commit,
            repo_root=Path(args.root),
            base=args.base,
            document=document,
            requirements_bytes=requirements,
            expected_requirements_digest=args.requirements_digest,
            evidence_bytes=evidence,
            expected_evidence_digest=args.evidence_digest,
        )
        if compilation_report is not None:
            report["compilation_replay"] = compilation_report
            for residual in compilation_report["findings"]:
                if residual["required"]:
                    report["findings"].append(
                        {
                            "code": "COMPILATION_" + residual["code"],
                            "category": "COMPILATION_REPLAY",
                            "status": residual["status"],
                            "reason": residual["reason"],
                            "question": residual["question"],
                        }
                    )
                    findings.append(residual["reason"])
            report = _finalize(report)
        preventative = (
            _compare_prdel_documents(args, requirements)
            if args.compare_document
            else None
        )
        if preventative is not None:
            status = "FAIL" if preventative["verdict"] == "FAIL" else "UNKNOWN"
            reason = (
                "Selected preventative comparison is refuted."
                if status == "FAIL"
                else (
                    "Selected potential impacts and their validation "
                    "remain unresolved; no notices were sent."
                )
            )
            report["findings"].append(
                {
                    "code": "PREVENTATIVE_COMPARISON_" + status,
                    "category": "PREVENTATIVE_COMPARISON_" + status,
                    "status": status,
                    "reason": reason,
                    ("question"): (
                        "Inspect the separate source-bound "
                        "preventative report and discharge its exact "
                        "test obligations."
                    ),
                }
            )
            report = _finalize(report)
            findings.append(reason)
        if args.render or args.impact_dag:
            if document is None:
                raise ValueError("rendering requires an explicit document")
            value = (
                render_impact_mermaid(document)
                if args.impact_dag
                else render_prdel(document)
            )
            if args.json:
                _prdel_emit(
                    {
                        "schema_version": "verifier-prdel-render-1",
                        "operation": "impact-dag" if args.impact_dag else "render",
                        "rendered": value,
                        "report": report,
                        "preventative": preventative,
                    },
                    args,
                )
            else:
                _prdel_emit(value, args)
            return 0
        if args.json or args.output:
            _prdel_emit(
                {
                    "schema_version": "verifier-prdel-cli-1",
                    "status": report["status"],
                    "report": report,
                    "findings": findings,
                    "preventative": preventative,
                },
                args,
            )
        else:
            print(f"[{report['status']}] PRDEL exact-source description gate")
            for finding in report.get("findings", []):
                print(
                    (
                        f"  - "
                        f"{finding.get('category', 'UNRESOLVED')}"
                        f": "
                        f"{finding.get('reason', '')}"
                    )
                )
                if finding.get("question"):
                    print(f"    {finding['question']}")
            print("Boundary: " + report["claim_boundary"])
            if preventative is not None:
                print("Preventative notices: NOT_SENT")
                for notice in preventative["notices"]:
                    print("  - " + notice["rule"] + ": " + notice["question"])
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(report["status"], 2)
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        ImportError,
        SyntaxError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        assessed = report
        report = _prdel_input_error()
        if isinstance(
            error, (OSError, ImportError, subprocess.SubprocessError)
        ) and not isinstance(error, FileNotFoundError):
            report["status"] = report["source_grounding_status"] = report[
                "semantic_status"
            ] = "UNKNOWN"
            report["claim_boundary"] = (
                "Selected input or trusted tooling is "
                "unavailable; absence or proposition falsity is "
                "not established."
            )
            report["findings"][0].update(
                code="UNAVAILABLE_INPUT",
                category="UNAVAILABLE_INPUT",
                status="UNKNOWN",
                reason=(
                    "Selected input could not be read or trusted "
                    "tooling is unavailable."
                ),
                question=(
                    "Restore readable selected inputs and trusted "
                    "tooling, then rerun validation."
                ),
            )
            if assessed is not None:
                assessed["findings"] = list(assessed["findings"]) + report["findings"]
                report = _finalize(assessed)
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": "verifier-prdel-cli-1",
                        "status": report["status"],
                        "report": report,
                        "findings": [report["findings"][0]["reason"]],
                    },
                    indent=2,
                )
            )
        else:
            print("[" + report["status"] + "] " + report["findings"][0]["reason"])
        return 1 if report["status"] == "FAIL" else 2



def add_gate_parsers(subparsers: Any) -> None:
    gate_parser = subparsers.add_parser(
        "gate",
        help="Plan and run bounded automation, scan selected inputs, and check retained receipts.",
    )
    gate_parser.add_argument("--object", help="Exact object identifier in the selected root objects.vstd.")
    gate_parser.add_argument("--obligation", help="Exact readable obligation identifier printed by package polish.")
    gate_parser.add_argument("--source-root", help="Repository root for a manifest-object gate (default: current directory).")
    gate_parser.add_argument("--json", action="store_true", help="Emit a structured manifest-object gate result.")
    sub = gate_parser.add_subparsers(dest="gate_subcommand")
    from verifier.runtime.gate_pipeline import add_pipeline_parsers
    add_pipeline_parsers(sub)
    from verifier.runtime.secret_gate import add_secret_parser
    add_secret_parser(sub)

    # vstd gate pr
    pr_parser = sub.add_parser(
        "pr",
        help="Bounded metadata diagnostics, or explicitly selected versioned PRDEL exact-source checks.",
        description=(
            "Ordinary --file/--text checks bounded metadata only. The explicit "
            "verifier-prdel-1 or verifier-prdel-2 contract, or modern selectors, require base/head and "
            "compile exact-diff facts with inspectable expert rules, "
            "validate residual coverage, and render explanations or "
            "impact graphs. Validation exits 0 for bounded PASS, 1 "
            "for FAIL (known missing or failed obligations), and 2 "
            "for UNKNOWN (unresolved analysis, unsupported semantics "
            "or unavailable observations). Required NOT_RUN checks "
            "are visible and block clearance. Tool operations do not "
            "grant clearance."
        ),
    )
    pr_parser.add_argument(
        "--contract", choices=["verifier-prdel-1", "verifier-prdel-2", "verifier-prdel-shard-description-1"],
        help="Select the versioned exact-source PRDEL contract; explicit --base and --commit/--head required. Ordinary --file/--text remains bounded metadata diagnostics.",
    )
    pr_parser.add_argument(
        "--file", "-f", help="Path to pull-request description markdown file."
    )
    pr_parser.add_argument(
        "--text", "-t", help="Raw pull-request description markdown text."
    )
    pr_parser.add_argument(
        "--commit",
        "-c",
        "--head",
        help=(
            "Explicit reviewed head for a versioned PRDEL contract; a selected Git "
            "revision is resolved to an exact local commit."
        ),
    )
    pr_parser.add_argument(
        "--base",
        default=None,
        help="Explicit review base required by a versioned PRDEL contract; resolves to an exact local commit.",
    )
    pr_parser.add_argument(
        "--generate",
        action="store_true",
        help=(
            "Compile supported exact-source facts; generation exits "
            "0 when produced, independently of remaining gate "
            "obligations."
        ),
    )
    pr_parser.add_argument(
        "--template",
        action="store_true",
        help="With --generate, retain the unfilled manual template fallback.",
    )
    pr_parser.add_argument(
        "--compilation",
        action="store_true",
        help=(
            "With --generate, include versioned rule support, bounds "
            "and residuals around the document."
        ),
    )
    pr_parser.add_argument(
        "--definition",
        help=(
            "With --generate, select versioned authored definitions; "
            "intent remains separate from checked source facts."
        ),
    )
    pr_parser.add_argument(
        "--document",
        help="Machine-readable PRDEL document; can be used without --file/--text.",
    )
    pr_parser.add_argument(
        "--requirements",
        help="Explicit selected requirements file; requires --requirements-digest.",
    )
    pr_parser.add_argument(
        "--requirements-digest",
        help="Expected selected requirements digest; binds bytes, not authority.",
    )
    pr_parser.add_argument(
        "--evidence",
        help="Selected retained execution evidence file; requires --evidence-digest.",
    )
    pr_parser.add_argument(
        "--evidence-digest",
        help="Expected selected evidence digest; execution must still be checked.",
    )
    pr_parser.add_argument(
        "--replay-plan",
        help=(
            "Version-two only: exact replay-plan JSON selecting fixed pytest "
            "node identifiers; requires --replay-plan-digest."
        ),
    )
    pr_parser.add_argument(
        "--replay-plan-digest",
        help="Version-two only: expected lowercase SHA-256 of replay-plan bytes.",
    )
    pr_parser.add_argument(
        "--prdel-max-nodes",
        type=int,
        help="Version-two graph node limit (default 10000; fixed cap 200000).",
    )
    pr_parser.add_argument(
        "--prdel-max-edges",
        type=int,
        help="Version-two graph edge/frontier limit (default 20000; cap 400000).",
    )
    pr_parser.add_argument(
        "--prdel-max-operations",
        type=int,
        help="Version-two graph operation limit (default 200000; cap 50000000).",
    )
    pr_parser.add_argument(
        "--prdel-max-output-bytes",
        type=int,
        help="Version-two graph output limit (default 8388608; cap 33554432).",
    )
    pr_parser.add_argument(
        "--compare-document",
        action="append",
        default=[],
        help=(
            "Compare a pinned branch PRDEL document after "
            "recomputing its exact source graph; repeatable, at most "
            "32. Produces undelivered preventative notices."
        ),
    )
    pr_parser.add_argument(
        "--render",
        action="store_true",
        help=(
            "Render portable source-bound Markdown; --json also "
            "carries the separate report. Does not grant clearance."
        ),
    )
    pr_parser.add_argument(
        "--impact-dag",
        action="store_true",
        help=(
            "Render the retained impact graph as a Mermaid directed "
            "acyclic graph (DAG)."
        ),
    )
    pr_parser.add_argument(
        "--output",
        "-o",
        help=(
            "Write generated document, report or rendering using "
            "Unicode Transformation Format, 8-bit (UTF-8) and line "
            "feed (LF) endings."
        ),
    )
    pr_parser.add_argument(
        "--root", default=".", help="Repository root (default: current directory)."
    )
    pr_parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    pr_parser.add_argument("--manifest", help="With the sharded contract, select the immutable compilation manifest file.")
    pr_parser.add_argument("--manifest-digest", help="Externally selected manifest SHA-256, lowercase hexadecimal.")
    pr_parser.add_argument("--shard", action="append", default=[], help="Select each immutable shard file in exact order; repeatable.")
    pr_parser.add_argument("--shard-digest", action="append", default=[], help="Externally selected SHA-256 for each ordered shard; repeatable.")
    pr_parser.add_argument("--source-digest", help="Externally selected exact source digest for the sharded contract.")
    pr_parser.add_argument("--compilation-residuals", help="Select the complete required compilation residual inventory as JSON.")
    pr_parser.add_argument("--packet-budget-bytes", type=int, help="Explicit aggregate packet allocation within the retained-source receiver profile; required by the sharded contract.")

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
    if sub is None:
        from verifier.runtime.manifest_gate import handle_manifest_gate
        return handle_manifest_gate(args)
    if any(getattr(args, name, None) is not None for name in ("object", "obligation", "source_root")):
        raise ValueError("Manifest-object selectors cannot be combined with a gate subcommand.")
    if sub == "secrets":
        from verifier.runtime.secret_gate import handle_secret_command
        return handle_secret_command(args)
    if sub in {"init", "plan", "run", "check"}:
        from verifier.runtime.gate_pipeline import handle_pipeline_command
        return handle_pipeline_command(args)

    if sub == "pr":
        modern = _has_shard_selectors(args) or getattr(args, "contract", None) is not None or any(
            getattr(args, name, None) is not None
            for name in (
                "base", "definition",
                "document", "requirements", "requirements_digest", "evidence",
                "evidence_digest", "replay_plan", "replay_plan_digest",
                "prdel_max_nodes", "prdel_max_edges", "prdel_max_operations",
                "prdel_max_output_bytes", "output",
            )
        ) or any(
            bool(getattr(args, name, None))
            for name in ("generate", "template", "compilation", "compare_document", "render", "impact_dag")
        )
        if modern:
            return _handle_prdel_command(args)
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
        # Preserve the selected link/reparse point for the scanner's refusal.
        target = Path(args.target).absolute()
        scanned, violations = run_paths_gate(target, additional_excludes=args.exclude)
        safe_violations = []
        target_is_file = target.is_file()
        for v in violations:
            raw_file = str(v.get("file", ""))
            if target_is_file:
                locator = target.name
            else:
                try:
                    locator = Path(raw_file).absolute().relative_to(target).as_posix()
                except (OSError, ValueError):
                    locator = Path(raw_file).name or "target"
            if not locator or locator == ".":
                locator = target.name or "target"
            if any(pattern.search(locator) for _label, pattern in SECRET_PATTERNS) or any(
                pattern.search(locator) for _label, pattern in PATH_PATTERNS
            ):
                safe_file = "<redacted>"
            else:
                safe_file = locator
            label = v.get("label", "")
            if label not in {
                "Windows drive path",
                "UNC share path",
                "POSIX user home",
                "Absolute file URI",
            }:
                label = "incomplete scan"
            safe_violations.append({
                "file": safe_file,
                "line": int(v.get("line", 0)),
                "label": label,
            })
        if args.json:
            print(json.dumps({
                "status": "PASS" if not violations else "FAIL",
                "scanned_files": scanned,
                "violations": safe_violations,
            }, indent=2))
        else:
            if violations:
                print(f"[FAIL] Absolute paths detected in {len(violations)} locations:")
                for v in safe_violations:
                    print(f"  - {v['file']}:{v['line']} [{v['label']}]")
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

