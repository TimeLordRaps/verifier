"""Verifier Standard (VSTD) secret gate over exactly selected raw text artifacts.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind the finite scope and installed scanner. Unicode Transformation Format,
8-bit (UTF-8); universally unique identifier (UUID). PASS means zero findings under the
pinned Gitleaks rules on selected raw UTF-8 text; it is not universal absence of
secrets, an execution sandbox, a security-tier certificate or a profile approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any

REQUEST = "vstd.secret-gate.request/1"
RECEIPT = "vstd.secret-gate.receipt/1"
VERSION = "8.30.1"
CONFIGURATION = (
    b'title = "VSTD proposal: pinned Gitleaks defaults, no local baseline"\n'
    b'[extend]\nuseDefault = true\n'
)
CONFIGURATION_SHA256 = hashlib.sha256(CONFIGURATION).hexdigest()
COVERAGE = ["every-byte-artifact", "no-implicit-exclusions", "representation-coverage-explicit"]
MODES = {"staged-index", "outgoing-history", "preflight-input", "preflight-output"}
LIMIT_FILE = 2 * 1024 * 1024
LIMIT_TOTAL = 32 * 1024 * 1024
LIMIT_REQUEST = 1024 * 1024
LIMIT_REPORT = 2 * 1024 * 1024
LIMIT_BINARY = 64 * 1024 * 1024
LIMIT_ARTIFACTS = 1000
WALL_SECONDS = 30
BOUNDARY = (
    "Exact selected raw UTF-8 text under pinned Gitleaks rules, including their "
    "compiled rule decisions. No baseline, ignore file or allow-comment exemption. "
    "Binary, archive and decoded representations are outside this version; "
    "no universal secret-free, model correctness, sandbox or profile claim."
)


class Unavailable(Exception):
    """Only fixed metadata reason codes may cross the reporting boundary."""

    def __init__(self, reason: str):
        self.reason = reason


class Contradiction(Unavailable):
    """A positively contradicted selected binding is a failed gate."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in rows:
        if key in result:
            raise Unavailable("DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def _json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Unavailable("NONFINITE_JSON")))


def _keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise Unavailable("REQUEST_FIELDS_UNSUPPORTED")


def _hex(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _read(path: Path, limit: int) -> bytes:
    if not path.is_absolute():
        raise Unavailable("ABSOLUTE_REGULAR_PATH_REQUIRED")
    if path.drive.startswith("\\\\"):
        raise Unavailable("REMOTE_PATH_UNSUPPORTED")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise Unavailable("LINKED_PATH_UNSUPPORTED")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise Unavailable("REGULAR_FILE_REQUIRED")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Unavailable("SELECTED_BYTE_LIMIT")
    return raw


def _environment(temporary: Path) -> dict[str, str]:
    result = {}
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value is not None:
            result[key] = value
    result.update(TEMP=str(temporary), TMP=str(temporary), HOME=str(temporary),
                  USERPROFILE=str(temporary), XDG_CONFIG_HOME=str(temporary),
                  GIT_TERMINAL_PROMPT="0")
    return result


def _process(argv: list[str], content: bytes, temporary: Path,
             timeout: float) -> tuple[int, bytes]:
    """Trusted scanner only; bounded pipes and direct-child lifecycle, not a sandbox."""
    if timeout <= 0:
        raise Unavailable("SCANNER_TIMEOUT")
    child = None
    workers = []
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    feed_failed = threading.Event()

    def drain(pipe: Any, target: bytearray) -> None:
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                if len(target) + len(chunk) > LIMIT_REPORT:
                    exceeded.set()
                    return
                target.extend(chunk)
        except (OSError, ValueError):
            exceeded.set()
        finally:
            pipe.close()

    def feed() -> None:
        try:
            if child.stdin.write(content) != len(content):
                feed_failed.set()
            child.stdin.close()
        except (OSError, ValueError):
            feed_failed.set()

    try:
        child = subprocess.Popen(argv, shell=False, cwd=temporary,
                                 env=_environment(temporary), stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for pipe, target in zip((child.stdout, child.stderr), buffers):
            worker = threading.Thread(target=drain, args=(pipe, target), daemon=True)
            workers.append(worker)
        workers.append(threading.Thread(target=feed, daemon=True))
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if exceeded.is_set():
                raise Unavailable("SCANNER_OUTPUT_LIMIT")
            if time.monotonic() >= deadline:
                raise Unavailable("SCANNER_TIMEOUT")
            time.sleep(.01)
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise Unavailable("OWNED_SCANNER_EXIT_UNCONFIRMED") from None
            for worker in workers:
                worker.join(timeout=2)
            if any(worker.is_alive() for worker in workers):
                raise Unavailable("SCANNER_PIPE_LIFECYCLE_UNCONFIRMED")
    if exceeded.is_set():
        raise Unavailable("SCANNER_OUTPUT_LIMIT")
    if feed_failed.is_set():
        raise Unavailable("SCANNER_STDIN_INCOMPLETE")
    return child.returncode, bytes(buffers[0])


def _scan(binary: Path, configuration: Path, content: bytes, temporary: Path,
          timeout: float) -> int:
    report = temporary / "findings.json"
    if report.exists():
        report.unlink()
    code, _ = _process(
        [str(binary), "stdin", "--config", str(configuration), "--no-banner",
         "--no-color", "--redact=100", "--exit-code", "10", "--report-format", "json",
         "--report-path", str(report), "--log-level", "error",
         "--gitleaks-ignore-path", str(temporary / "absent-ignore-file"),
         "--ignore-gitleaks-allow", "--max-decode-depth", "0",
         "--max-archive-depth", "0"], content, temporary, timeout)
    if code not in {0, 10}:
        raise Unavailable("SCANNER_ERROR_DETAILS_SUPPRESSED")
    rows = _json(_read(report, LIMIT_REPORT))
    if type(rows) is not list or len(rows) > 10000:
        raise Unavailable("SCANNER_REPORT_UNSUPPORTED")
    if any(type(row) is not dict or type(row.get("RuleID")) is not str
           or type(row.get("StartLine")) is not int for row in rows):
        raise Unavailable("SCANNER_REPORT_UNSUPPORTED")
    if (code == 0) != (not rows):
        raise Unavailable("SCANNER_EXIT_REPORT_MISMATCH")
    # Never return matches, lines, secret fields, paths or backend-supplied labels.
    return len(rows)


def _base() -> dict[str, Any]:
    return {"schema": RECEIPT, "request_id": None, "scope_manifest_sha256": None,
            "outcome": "UNKNOWN", "coverage_complete": False, "artifact_count": 0,
            "artifacts_scanned": 0, "findings_count": 0, "findings": [],
            "scanner": None, "reason_codes": [], "claim_boundary": BOUNDARY,
            "mechanism_sha256": _digest(Path(__file__).read_bytes())}


def _validate(value: Any, receipt: dict[str, Any]) -> list[dict[str, Any]]:
    _keys(value, {"schema", "request_id", "mode", "scope_manifest_sha256", "selection",
                  "artifacts", "coverage_requirements", "scanner_policy"})
    if value["schema"] != REQUEST or value["mode"] not in MODES:
        raise Unavailable("REQUEST_SCHEMA_OR_MODE_UNSUPPORTED")
    identity = value["request_id"]
    if type(identity) is not str or str(uuid.UUID(identity)) != identity:
        raise Unavailable("CANONICAL_REQUEST_UUID_REQUIRED")
    if not _hex(value["scope_manifest_sha256"]):
        raise Unavailable("SCOPE_DIGEST_REQUIRED")
    receipt.update(request_id=identity, scope_manifest_sha256=value["scope_manifest_sha256"])
    artifacts = value["artifacts"]
    if type(artifacts) is not list or len(artifacts) > LIMIT_ARTIFACTS:
        raise Unavailable("ARTIFACT_COUNT_LIMIT")
    receipt["artifact_count"] = len(artifacts)
    if type(value["selection"]) is not dict:
        raise Unavailable("SELECTION_METADATA_REQUIRED")
    coverage = value["coverage_requirements"]
    if type(coverage) is not list or len(coverage) != len(COVERAGE) or set(coverage) != set(COVERAGE):
        raise Unavailable("COVERAGE_REQUIREMENT_UNSUPPORTED")
    policy = value["scanner_policy"]
    _keys(policy, {"name", "version", "configuration_sha256", "binary_sha256"})
    if policy["name"] != "gitleaks" or policy["version"] != VERSION:
        raise Unavailable("SCANNER_POLICY_UNSUPPORTED")
    if not _hex(policy["configuration_sha256"]) or not _hex(policy["binary_sha256"]):
        raise Unavailable("SCANNER_INSTALLATION_PIN_PENDING")
    if policy["configuration_sha256"] != CONFIGURATION_SHA256:
        raise Unavailable("SCANNER_CONFIGURATION_UNSUPPORTED")
    receipt["scanner"] = dict(policy)
    ids = set()
    total = 0
    for artifact in artifacts:
        _keys(artifact, {"id", "kind", "content_path", "bytes", "content_sha256"},
              {"selected_path"})
        if type(artifact["id"]) is not str or not artifact["id"] or artifact["id"] in ids:
            raise Unavailable("ARTIFACT_ID_INVALID_OR_DUPLICATE")
        ids.add(artifact["id"])
        if type(artifact["kind"]) is not str or not artifact["kind"]:
            raise Unavailable("ARTIFACT_KIND_REQUIRED")
        if type(artifact["content_path"]) is not str or not _hex(artifact["content_sha256"]):
            raise Unavailable("ARTIFACT_BINDING_REQUIRED")
        if type(artifact["bytes"]) is not int or not 0 <= artifact["bytes"] <= LIMIT_FILE:
            raise Unavailable("SELECTED_BYTE_LIMIT")
        if "selected_path" in artifact and type(artifact["selected_path"]) is not str:
            raise Unavailable("SELECTION_METADATA_UNSUPPORTED")
        total += artifact["bytes"]
        if total > LIMIT_TOTAL:
            raise Unavailable("SELECTED_TOTAL_BYTE_LIMIT")
    scope = {key: value[key] for key in ("mode", "selection", "coverage_requirements", "scanner_policy")}
    scope["artifacts"] = [{key: item for key, item in artifact.items() if key != "content_path"}
                          for artifact in artifacts]
    if _digest(_canonical(scope)) != value["scope_manifest_sha256"]:
        raise Contradiction("SCOPE_MANIFEST_BINDING_MISMATCH")
    return artifacts


def _content(artifact: dict[str, Any]) -> bytes:
    raw = _read(Path(artifact["content_path"]), LIMIT_FILE)
    if len(raw) != artifact["bytes"] or _digest(raw) != artifact["content_sha256"]:
        raise Contradiction("ARTIFACT_CONTENT_BINDING_MISMATCH")
    if b"\0" in raw or raw.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"BZh")):
        raise Unavailable("BINARY_OR_ARCHIVE_COVERAGE_UNSUPPORTED")
    try:
        raw.decode("utf-8")
    except UnicodeError:
        raise Unavailable("UTF8_REPRESENTATION_UNAVAILABLE") from None
    return raw


def assess_secret_request(request_path: str | Path, *, scanner_binary: str | Path | None = None,
                          scanner_configuration: str | Path | None = None) -> dict[str, Any]:
    """Recompute the selected gate now. A carried receipt does not authorize changed bytes."""
    receipt = _base()
    try:
        path = Path(request_path).absolute()
        request_raw = _read(path, LIMIT_REQUEST)
        value = _json(request_raw)
        artifacts = _validate(value, receipt)
        if not artifacts:
            receipt.update(outcome="NOOP", coverage_complete=True,
                           reason_codes=["EMPTY_EXACT_SELECTION"])
            return receipt
        if scanner_binary is None or scanner_configuration is None:
            raise Unavailable("SCANNER_BACKEND_UNAVAILABLE")
        original_binary = Path(scanner_binary)
        original_configuration = Path(scanner_configuration)
        binary_raw = _read(original_binary, LIMIT_BINARY)
        configuration_raw = _read(original_configuration, LIMIT_REQUEST)
        if _digest(binary_raw) != receipt["scanner"]["binary_sha256"]:
            raise Contradiction("SCANNER_BINARY_BINDING_MISMATCH")
        if _digest(configuration_raw) != receipt["scanner"]["configuration_sha256"]:
            raise Contradiction("SCANNER_CONFIGURATION_BINDING_MISMATCH")
        if configuration_raw != CONFIGURATION:
            raise Unavailable("SCANNER_CONFIGURATION_UNSUPPORTED")
        deadline = time.monotonic() + WALL_SECONDS
        with tempfile.TemporaryDirectory(prefix="vstd-secret-gate-") as directory:
            temporary = Path(directory)
            binary = temporary / ("scanner.exe" if os.name == "nt" else "scanner")
            binary.write_bytes(binary_raw)
            binary.chmod(0o700)
            configuration = temporary / "scanner.toml"
            configuration.write_bytes(configuration_raw)
            code, version = _process([str(binary), "version"], b"", temporary,
                                     min(5, deadline - time.monotonic()))
            if code != 0 or version.strip() not in {VERSION.encode(), ("v" + VERSION).encode()}:
                raise Unavailable("SCANNER_VERSION_UNAVAILABLE_OR_MISMATCH")
            for index, artifact in enumerate(artifacts, 1):
                try:
                    raw = _content(artifact)
                    count = _scan(binary, configuration, raw, temporary,
                                  deadline - time.monotonic())
                    if _content(artifact) != raw:
                        raise Contradiction("ARTIFACT_CHANGED_DURING_SCAN")
                    receipt["artifacts_scanned"] += 1
                    if count:
                        receipt["findings"].append({"artifact_index": index, "count": count})
                        receipt["findings_count"] += count
                except Contradiction as error:
                    receipt["outcome"] = "FAIL"
                    receipt["reason_codes"].append(error.reason)
                except Unavailable as error:
                    receipt["reason_codes"].append(error.reason)
                except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
                    receipt["reason_codes"].append("ARTIFACT_SCAN_UNAVAILABLE_DETAILS_SUPPRESSED")
            # Rebind every selection, including files scanned earlier, before emitting a receipt.
            for artifact in artifacts:
                _content(artifact)
            if _read(path, LIMIT_REQUEST) != request_raw:
                raise Contradiction("REQUEST_CHANGED_DURING_SCAN")
            if _read(original_binary, LIMIT_BINARY) != binary_raw:
                raise Contradiction("SCANNER_BINARY_CHANGED_DURING_SCAN")
            if _read(original_configuration, LIMIT_REQUEST) != configuration_raw:
                raise Contradiction("SCANNER_CONFIGURATION_CHANGED_DURING_SCAN")
        receipt["coverage_complete"] = (not receipt["reason_codes"]
                                        and receipt["artifacts_scanned"] == len(artifacts))
        if receipt["findings_count"]:
            receipt["outcome"] = "FAIL"
            receipt["reason_codes"].append("SECRET_FINDINGS")
        elif receipt["outcome"] != "FAIL":
            receipt["outcome"] = "PASS" if receipt["coverage_complete"] else "UNKNOWN"
    except Contradiction as error:
        receipt["outcome"] = "FAIL"
        receipt["reason_codes"].append(error.reason)
    except Unavailable as error:
        receipt["reason_codes"].append(error.reason)
    except KeyboardInterrupt:
        receipt["reason_codes"].append("SCAN_CANCELLED")
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        receipt["reason_codes"].append("SCAN_UNAVAILABLE_DETAILS_SUPPRESSED")
    if set(receipt["reason_codes"]) - {"SECRET_FINDINGS", "EMPTY_EXACT_SELECTION"}:
        receipt["coverage_complete"] = False
        if receipt["findings_count"]:
            receipt["outcome"] = "FAIL"
    receipt["reason_codes"] = sorted(set(receipt["reason_codes"]))
    return receipt


def add_secret_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("secrets", help="Scan exactly bound raw text; incomplete coverage is UNKNOWN.")
    parser.add_argument("--request", required=True, help="Selected secret-gate request JSON.")
    parser.add_argument("--scanner-binary", help="Absolute pinned local Gitleaks executable.")
    parser.add_argument("--scanner-config", help="Absolute pinned standalone configuration.")
    parser.add_argument("--json", action="store_true", help="Emit metadata-only receipt.")


def handle_secret_command(args: argparse.Namespace) -> int:
    receipt = assess_secret_request(args.request, scanner_binary=args.scanner_binary,
                                    scanner_configuration=args.scanner_config)
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print(f"[{receipt['outcome']}] Selected secret gate: "
              f"{receipt['artifacts_scanned']}/{receipt['artifact_count']} artifacts; "
              f"{receipt['findings_count']} findings.")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2, "NOOP": 3}[receipt["outcome"]]
