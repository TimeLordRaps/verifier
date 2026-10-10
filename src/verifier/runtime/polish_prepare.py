"""Reviewable local preparation for the command-line interface (CLI).

JavaScript Object Notation (JSON); Unicode Transformation Format, 8-bit (UTF-8).
Preparation discharges no numbered profile and never issues a polished nine-tier object.
It preserves evidence and secret bytes; publication remains a separate operation.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import json
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.runtime.artifact_snapshot import (
    Snapshot, capture, digest, ordinary, output_outside, record, write_new,
)
from verifier.runtime.gate import SECRET_PATTERNS

PREPARATION_POLICY = {"schema_version": "verifier-polish-preparation-policy-1",
    "fix": "explicit-source-prose-line-endings-and-final-newline",
    "suffixes": [".md", ".py", ".rst"], "evidence_mutation": False,
    "secret_mutation": False, "publication": False}
BOUNDARY = "Local source/prose preparation only; nine-tier polished-artifact issuance, quality, safety and publication are not established."


def mechanism_digest() -> str:
    root = Path(__file__).parent
    return digest(canonical_bytes({p: digest((root/p).read_bytes()) for p in
                                  ("polish_prepare.py", "artifact_snapshot.py", "gate.py")}))


def inspect(snapshot: Snapshot, normalize_text: bool) -> tuple[dict[str, bytes], list[dict[str, Any]], list[dict[str, Any]]]:
    planned = dict(snapshot.files)
    changes, findings = [], []
    for index, (name, raw) in enumerate(sorted(snapshot.files.items()), 1):
        suffix = Path(name).suffix
        if suffix not in {".py", ".md", ".rst", ".json"}:
            continue
        try:
            text = raw.decode("utf-8")
            if suffix == ".json":
                record(raw)
            if suffix == ".py":
                ast.parse(text)
        except (ValueError, UnicodeError, SyntaxError, RecursionError):
            findings.append({"file_index": index, "status": "FAIL", "reason": "INVALID_SOURCE_OR_JSON"})
            continue
        sensitive = any(pattern.search(text) for _, pattern in SECRET_PATTERNS)
        if sensitive:
            findings.append({"file_index": index, "status": "FAIL", "reason": "SECRET_PATTERN_REQUIRES_MANUAL_REVIEW"})
        if normalize_text and suffix in PREPARATION_POLICY["suffixes"] and not sensitive:
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            if normalized and not normalized.endswith("\n"):
                normalized += "\n"
            updated = normalized.encode("utf-8")
            if updated != raw:
                planned[name] = updated
                changes.append({"path": name, "before_digest": digest(raw), "after_digest": digest(updated),
                    "diff": "".join(difflib.unified_diff(text.splitlines(keepends=True),
                        normalized.splitlines(keepends=True), fromfile=name, tofile=name))})
    return planned, changes, findings


def prepare_artifact(artifact_path: str | Path, *, apply: bool = False,
                     normalize_text: bool = False) -> dict[str, Any]:
    before = capture(artifact_path)
    planned, changes, findings = inspect(before, normalize_text)
    if apply and not normalize_text:
        raise ValueError("--apply requires the explicitly selected --normalize-text fix")
    if apply and findings:
        raise ValueError("preparation findings block mutation; review the dry run")
    if capture(artifact_path).inventory() != before.inventory():
        raise ValueError("artifact changed during preparation")
    if apply:
        source = Path(artifact_path).absolute()
        targets = {}
        for change in changes:
            target = source if before.kind == "file" else source/change["path"]
            info = ordinary(target)
            if info.st_nlink != 1:
                raise ValueError("fix requires an ordinary file with no hard-link aliases")
            if target.read_bytes() != before.files[change["path"]]:
                raise ValueError("artifact changed before fix")
            targets[change["path"]] = target
        for change in changes:
            target = targets[change["path"]]
            if target.read_bytes() != before.files[change["path"]]:
                raise ValueError("artifact changed before fix")
            target.write_bytes(planned[change["path"]])
    after = capture(artifact_path)
    expected = Snapshot(before.kind, planned if apply else before.files)
    if after.inventory() != expected.inventory():
        raise ValueError("artifact differs after preparation")
    result = {"schema_version": "verifier-polish-preparation-1", "polished": False,
        "status": "FAIL" if findings else "UNKNOWN" if changes and not apply else "PASS",
        "mode": "APPLY" if apply else "DRY_RUN", "normalize_text": normalize_text,
        "policy": PREPARATION_POLICY, "policy_digest": digest(canonical_bytes(PREPARATION_POLICY)),
        "mechanism_digest": mechanism_digest(), "before": before.inventory(), "artifact": after.inventory(),
        "planned_artifact": Snapshot(before.kind, planned).inventory(), "changes": changes,
        "findings": findings, "claim_boundary": BOUNDARY}
    result["report_digest"] = digest(canonical_bytes(result))
    return result


def validate_preparation(raw: bytes, snapshot: Snapshot) -> dict[str, Any]:
    value = record(raw)
    if set(value) != {"schema_version", "polished", "status", "mode", "normalize_text", "policy", "policy_digest",
                     "mechanism_digest", "before", "artifact", "planned_artifact", "changes", "findings", "claim_boundary", "report_digest"}:
        raise ValueError("preparation fields differ")
    if (value["schema_version"] != "verifier-polish-preparation-1" or value["polished"] is not False
            or value["mode"] not in {"DRY_RUN", "APPLY"} or type(value["normalize_text"]) is not bool
            or value["policy"] != PREPARATION_POLICY or value["policy_digest"] != digest(canonical_bytes(PREPARATION_POLICY))
            or value["mechanism_digest"] != mechanism_digest() or value["artifact"] != snapshot.inventory()
            or value["report_digest"] != digest(canonical_bytes({k: v for k, v in value.items() if k != "report_digest"}))):
        raise ValueError("stale or inconsistent preparation")
    _, pending, findings = inspect(snapshot, value["normalize_text"])
    expected_status = "FAIL" if findings else "UNKNOWN" if pending else "PASS"
    if value["status"] != expected_status or value["findings"] != findings:
        raise ValueError("preparation status does not replay")
    if expected_status != "PASS":
        raise ValueError("preparation needs fixes or evidence")
    return value


def add_prepare_parser(commands: Any) -> None:
    parser = commands.add_parser("prepare", help="Review local preparation; preserve evidence and report exact-byte changes.")
    parser.add_argument("artifact")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Inspect and show planned diffs (the default).")
    mode.add_argument("--apply", action="store_true", help="Apply the explicitly requested safe text fix.")
    parser.add_argument("--normalize-text", action="store_true", help="Normalize source/prose line endings and final newline.")
    parser.add_argument("--output", help="Create a new preparation report outside the artifact.")
    parser.add_argument("--json", action="store_true")


def handle_prepare_command(args: argparse.Namespace) -> int:
    try:
        output_outside(args.output, args.artifact)
        if args.output and Path(args.output).exists():
            raise ValueError("output exists")
        result = prepare_artifact(args.artifact, apply=args.apply, normalize_text=args.normalize_text)
        write_new(args.output, result)
    except (OSError, ValueError, TypeError, RecursionError):
        result = {"schema_version": "verifier-polish-preparation-1", "status": "FAIL", "polished": False,
                  "reason": "PREPARATION_REFUSED", "claim_boundary": BOUNDARY}
    if args.json:
        print(json.dumps(result, sort_keys=True, allow_nan=False))
    else:
        print("[" + result["status"] + "] " + BOUNDARY)
        for change in result.get("changes", []):
            print(change["diff"])
        from verifier.runtime.polish_findings import project_reports, render_findings
        print(render_findings(project_reports(canonical_bytes(result))))
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
