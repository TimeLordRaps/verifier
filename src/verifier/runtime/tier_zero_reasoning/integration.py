# Terminology: intermediate representation (IR).
"""One-coordinate runner for Verifier Standard (VSTD) Tier-zero reason analysis.

The runner executes every lower-tier mechanism against one selected source tree
and emits one aggregate receipt.  It is deliberately read-only on source bytes;
generated files belong in an ignored work directory.  Mechanical completion is
not a package-polish or normative-conformance verdict. A directed acyclic graph
(DAG) closure claim requires a separate recomputation that this runner does not invent.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, NamedTuple, Sequence

from verifier.runtime.tier_zero_reasoning import ASSESSMENT_SCHEMA
from verifier.runtime.tier_zero_reasoning import conditional_dispatch, reasons_dsl


_HERE = Path(__file__).resolve().parent
ROOT_REASON_AUTHORITY_SCHEMA = "verifier-package-root-reason-authority-1"
_MAX_ROOT_REASONS_BYTES = 32 * 1024 * 1024


class RootReasonSelection(NamedTuple):
    """The sole authored reason input and its position-independent IR."""

    authority: dict[str, Any]
    ir: dict[str, Any]
    ir_digest: str
    classification_decisions: tuple[dict[str, str], ...]
    obligation_decisions: tuple[dict[str, Any], ...]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def select_root_reasons(root: Path) -> RootReasonSelection:
    """Select exactly ``ROOT/reasons.vstd`` beside ``ROOT/objects.vstd``.

    This is deliberately a source-independent input selector.  It does not
    import or consult the historical Python reason ledger, and it does not
    promote a parsed declaration to an established package verdict.  Callers
    must still reconcile the returned IR against the compiled object-obligation
    denominator.
    """

    selected_root = root.resolve(strict=True)
    objects_path = (selected_root / "objects.vstd").resolve(strict=True)
    reasons_path = (selected_root / "reasons.vstd").resolve(strict=True)
    if (
        objects_path.parent != selected_root
        or objects_path.name != "objects.vstd"
        or reasons_path.parent != selected_root
        or reasons_path.name != "reasons.vstd"
        or not objects_path.is_file()
        or not reasons_path.is_file()
    ):
        raise ValueError("PACKAGE_ROOT_REASON_SELECTION_INVALID")
    raw = reasons_path.read_bytes()
    if len(raw) > _MAX_ROOT_REASONS_BYTES:
        raise ValueError("PACKAGE_ROOT_REASONS_CAPACITY_EXCEEDED")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("PACKAGE_ROOT_REASONS_UTF8_INVALID") from exc
    parsed = reasons_dsl.parse(text, reasons_path.name)
    if (
        parsed["errors"]
        or parsed["malformed"]
        or parsed["ir"].get("unattributed")
    ):
        raise ValueError("PACKAGE_ROOT_REASONS_INVALID")

    decisions: list[dict[str, str]] = []
    obligation_decisions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    obligation_seen: set[tuple[str, str]] = set()
    classification_incomplete = False
    for reason in parsed["ir"]["reasons"]:
        claim = reason["claim"]
        if claim["form"] == "obligation":
            key = (claim["object"], claim["coordinate"])
            if key in obligation_seen:
                raise ValueError("PACKAGE_ROOT_OBLIGATION_REASON_DUPLICATE")
            obligation_seen.add(key)
            declared = [
                basis for basis in reason.get("basis", [])
                if basis.get("kind") == "declared"
            ]
            if not declared or not reason.get("note"):
                raise ValueError("PACKAGE_ROOT_OBLIGATION_REASON_INCOMPLETE")
            obligation_decisions.append({
                "reason_id": reason["id"],
                "object_id": claim["object"],
                "coordinate": claim["coordinate"],
                "decision": claim["decision"],
                "evidence": sorted({
                    token
                    for basis in declared
                    for token in basis.get("evidence", [])
                }),
                "reason": reason["note"],
            })
            continue
        if claim["form"] not in {"applies", "denial"}:
            continue
        key = (claim["object"], claim["kind"])
        if key in seen:
            raise ValueError("PACKAGE_ROOT_REASON_DECISION_DUPLICATE")
        seen.add(key)
        declared = [
            basis for basis in reason.get("basis", [])
            if basis.get("kind") == "declared" and basis.get("evidence")
        ]
        if (
            claim["object"] not in reason.get("about", [])
            or not declared
            or not reason.get("note", "").strip()
        ):
            classification_incomplete = True
        decisions.append({
            "reason_id": reason["id"],
            "object_id": claim["object"],
            "object_kind": claim["kind"],
            "decision": (
                "APPLIES" if claim["form"] == "applies"
                else "DOES_NOT_APPLY"
            ),
        })
    if classification_incomplete:
        raise ValueError("PACKAGE_ROOT_CLASSIFICATION_REASON_INCOMPLETE")
    decisions.sort(key=lambda row: (
        row["object_id"], row["object_kind"], row["reason_id"],
    ))
    obligation_decisions.sort(key=lambda row: (
        row["object_id"], row["coordinate"], row["reason_id"],
    ))
    authority = {
        "schema_version": ROOT_REASON_AUTHORITY_SCHEMA,
        "path": "reasons.vstd",
        "sha256": _digest(raw),
        "authored_input_count": 1,
        "objects_registry_path": "objects.vstd",
        "only_authored_reason_input": True,
    }
    return RootReasonSelection(
        authority=authority,
        ir=parsed["ir"],
        ir_digest=reasons_dsl.ir_digest(parsed["ir"]),
        classification_decisions=tuple(decisions),
        obligation_decisions=tuple(obligation_decisions),
    )


def documented_applicability_answers(
    selection: RootReasonSelection,
    objects: Sequence[dict[str, Any]],
) -> tuple[dict[str, str], ...]:
    """Select fail-closed APPLIES answers for answerable compiled cells.

    The sole authored ``reasons.vstd`` may conservatively retain a kind's
    obligations while the compiled registry cell remains ``UNRESOLVED`` or
    conservatively supersede a compiled ``DOES_NOT_APPLY`` whose absence is not
    relied on.  This function deliberately excludes denials: documented
    non-applicability is never enough to erase an obligation.  It also does not
    mutate the supplied registry rows or claim that source semantics have been
    established.
    """

    rows = {
        row.get("object_id"): row
        for row in objects
        if isinstance(row, dict) and isinstance(row.get("object_id"), str)
    }
    reasons = {
        reason.get("id"): reason
        for reason in selection.ir.get("reasons", [])
        if isinstance(reason, dict) and isinstance(reason.get("id"), str)
    }
    answers: list[dict[str, str]] = []
    for decision in selection.classification_decisions:
        if decision["decision"] != "APPLIES":
            continue
        object_id = decision["object_id"]
        kind = decision["object_kind"]
        row = rows.get(object_id)
        classification = row.get("classification") if isinstance(row, dict) else None
        cell = classification.get(kind) if isinstance(classification, dict) else None
        if (
            not isinstance(cell, dict)
            or cell.get("status") not in {"UNRESOLVED", "DOES_NOT_APPLY"}
        ):
            continue
        reason = reasons.get(decision["reason_id"])
        declared = [
            basis
            for basis in reason.get("basis", [])
            if isinstance(basis, dict)
            and basis.get("kind") == "declared"
            and basis.get("evidence")
        ] if isinstance(reason, dict) else []
        about = reason.get("about", []) if isinstance(reason, dict) else []
        note = reason.get("note", "") if isinstance(reason, dict) else ""
        if object_id not in about or not declared or not isinstance(note, str) or not note.strip():
            raise ValueError("PACKAGE_ROOT_APPLICABILITY_REASON_INCOMPLETE")
        answers.append(dict(decision))
    answers.sort(key=lambda row: (
        row["object_id"], row["object_kind"], row["reason_id"],
    ))
    return tuple(answers)


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("TIER_ZERO_REASONING_GIT_COORDINATE_UNAVAILABLE")
    return completed.stdout


def _source_coordinate(root: Path) -> dict[str, Any]:
    names = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    selected = [name for name in names.decode("utf-8", errors="surrogateescape").split("\0") if name]
    rows: list[tuple[str, int, str]] = []
    for name in sorted(selected):
        path = root / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        rows.append((name, len(raw), hashlib.sha256(raw).hexdigest()))
    status = _git(root, "status", "--porcelain=v1", "-z")
    return {
        "head": _git(root, "rev-parse", "HEAD").decode("ascii").strip(),
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD").decode("ascii").strip(),
        "status_entry_count": len([item for item in status.split(b"\0") if item]),
        "status_sha256": _digest(status),
        "selected_file_count": len(rows),
        "selected_files_sha256": _digest(_canonical(rows)),
    }


def _step(
    name: str,
    command: Sequence[str],
    *,
    root: Path,
    output: Path,
    environment: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    log = output / (name + ".log")
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(root),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
        raw = completed.stdout
        exit_code: int | None = completed.returncode
        state = "COMPLETED" if completed.returncode == 0 else "FAILED"
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or b"") + b"\n[TIMEOUT]\n"
        exit_code = None
        state = "TIMED_OUT"
    log.write_bytes(raw)
    result = {
        "name": name,
        "state": state,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "argv": list(command),
        "log": str(log),
        "log_sha256": _digest(raw),
    }
    print(
        f"[{state}] {name} exit={exit_code} elapsed={result['elapsed_seconds']:.3f}s",
        file=sys.stderr,
        flush=True,
    )
    return result


def _blocked(name: str, dependency: str) -> dict[str, Any]:
    return {
        "name": name,
        "state": "BLOCKED",
        "exit_code": None,
        "reason": "required prior component did not complete: " + dependency,
    }


def _observations(paths: Sequence[Path], output: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        parsed = reasons_dsl.parse(text, path.name)
        if parsed["errors"] or parsed["malformed"]:
            raise ValueError("TIER_ZERO_REASONING_OBSERVATION_INPUT_INVALID")
        normalized = reasons_dsl.observation_ir(parsed["ir"])
        rows.extend({**row, "source": path.name} for row in normalized["observations"])
        sources.append({
            "path": str(path),
            "ir_digest": reasons_dsl.ir_digest(parsed["ir"]),
            "observation_count": len(normalized["observations"]),
        })
    report = {
        "schema_version": "verifier-tier-zero-falsifier-observations-1",
        "sources": sources,
        "observations": rows,
        "claim_boundary": (
            "Static normalization preserves the subject, treatment, witness, expectation, and independence "
            "questions; runtime test and observer outcomes require witness receipts."
        ),
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return report


def _reconcile_witness_documents(
    check: dict[str, Any],
    observations: dict[str, Any],
    witness_receipts: dict[str, Any],
) -> dict[str, Any]:
    """Join runtime witnesses to their normalized observations without upgrading claims."""

    receipts: dict[str, dict[str, Any]] = {}
    duplicated: set[str] = set()
    for receipt in witness_receipts.get("receipts", []):
        identifier = receipt.get("id")
        if not isinstance(identifier, str):
            continue
        if identifier in receipts:
            duplicated.add(identifier)
        receipts[identifier] = receipt
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    missing: list[str] = []
    for observation in observations.get("observations", []):
        witness = observation.get("witness", {})
        if witness.get("kind") not in {"test", "observer"}:
            continue
        locator = witness.get("locator")
        reason_id = observation.get("subject", {}).get("reason")
        receipt = receipts.get(locator) if isinstance(locator, str) else None
        static = check.get("reasons", {}).get(reason_id, {})
        if receipt is None:
            disposition = "UNKNOWN"
            rationale = "no runtime receipt matches the observation witness locator"
            missing.append(str(locator))
            receipt_status = None
            tier5_eligible = False
        else:
            receipt_status = receipt.get("status")
            tier5_eligible = bool(receipt.get("tier5_eligible"))
            rationale = str(receipt.get("rationale", ""))
            if receipt_status == "HOLDS" and tier5_eligible:
                disposition = "OBSERVED_TIER5_ELIGIBLE"
            elif receipt_status == "HOLDS":
                disposition = "OBSERVED_NONINDEPENDENT"
            elif receipt_status == "UNKNOWN":
                disposition = "UNKNOWN"
            else:
                disposition = "REFUTED"
        counts[disposition] = counts.get(disposition, 0) + 1
        rows.append({
            "observation_id": observation.get("id"),
            "reason_id": reason_id,
            "witness_locator": locator,
            "expectation": observation.get("expectation"),
            "static_checker_status": static.get("status"),
            "static_checker_detail": static.get("detail"),
            "runtime_receipt_status": receipt_status,
            "tier5_eligible": tier5_eligible,
            "observation_disposition": disposition,
            "rationale": rationale,
            "claim_status": "UNKNOWN",
        })
    mechanism_status = "PASS" if rows and not missing and not duplicated else "UNKNOWN"
    return {
        "schema_version": "verifier-tier-zero-witness-reconciliation-1",
        "mechanism_status": mechanism_status,
        "counts": counts,
        "observations": rows,
        "missing_receipts": sorted(set(missing)),
        "duplicated_receipts": sorted(duplicated),
        "closure_recomputation": "NOT_ESTABLISHED",
        "claim_boundary": (
            "The join establishes which runtime receipt belongs to each normalized test or observer "
            "observation. A holding receipt does not by itself establish the reason's external claim, "
            "and this prototype does not recompute derivation-DAG closure from runtime observations."
        ),
    }


def _reconcile_witnesses(
    check_path: Path,
    observations_path: Path,
    witness_path: Path,
    output: Path,
) -> dict[str, Any]:
    report = _reconcile_witness_documents(
        json.loads(check_path.read_text(encoding="utf-8")),
        json.loads(observations_path.read_text(encoding="utf-8")),
        json.loads(witness_path.read_text(encoding="utf-8")),
    )
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report


def _reconcile_obligation_reason_documents(
    reason_ir: dict[str, Any],
    check: dict[str, Any],
    objects_dump: dict[str, Any],
) -> dict[str, Any]:
    """Reconcile exact REQUIRED reasons with the compiled open denominator.

    Classification reasons remain visible as auxiliary applicability records,
    but one broad object/kind claim cannot stand in for several exact compiled
    obligations.  Package-polish reasons for later tiers may coexist in the one
    root file; the tier that owns their denominator reconciles them.
    """

    accepted_statuses = {"ESTABLISHED", "DOCUMENTED"}
    open_rows = objects_dump.get("open_obligations")
    if not isinstance(open_rows, list):
        raise ValueError("TIER_ZERO_REASONING_OPEN_OBLIGATIONS_INVALID")

    rows_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    rows_by_role: dict[tuple[str, str], list[dict[str, Any]]] = {}
    status_counts: dict[str, int] = {}
    for row in open_rows:
        if not isinstance(row, dict):
            raise ValueError("TIER_ZERO_REASONING_OPEN_OBLIGATION_ROW_INVALID")
        object_id = row.get("object_id")
        kind = row.get("kind")
        obligation = row.get("obligation")
        status = row.get("status")
        if not all(isinstance(value, str) for value in (object_id, kind, obligation, status)):
            raise ValueError("TIER_ZERO_REASONING_OPEN_OBLIGATION_FIELDS_INVALID")
        key = (object_id, obligation)
        if key in rows_by_key:
            raise ValueError("TIER_ZERO_REASONING_OPEN_OBLIGATION_DUPLICATE")
        normalized = {
            "object_id": object_id,
            "kind": kind,
            "obligation": obligation,
            "status": status,
        }
        rows_by_key[key] = normalized
        rows_by_role.setdefault((object_id, kind), []).append(normalized)
        status_counts[status] = status_counts.get(status, 0) + 1

    check_reasons = check.get("reasons")
    if not isinstance(check_reasons, dict):
        raise ValueError("TIER_ZERO_REASONING_CHECK_REASONS_INVALID")

    candidates: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    classification_references: list[dict[str, Any]] = []
    for reason in reason_ir.get("reasons", []):
        claim = reason.get("claim", {})
        form = claim.get("form")
        reason_id = reason.get("id")
        if form in {"applies", "denial"}:
            object_id = claim.get("object")
            kind = claim.get("kind")
            if not all(isinstance(value, str) for value in (reason_id, object_id, kind)):
                raise ValueError("TIER_ZERO_REASONING_CLASSIFICATION_REASON_INVALID")
            checked = check_reasons.get(reason_id, {})
            classification_references.append({
                "reason_id": reason_id,
                "object_id": object_id,
                "kind": kind,
                "decision": "APPLIES" if form == "applies" else "DOES_NOT_APPLY",
                "checker_status": checked.get("status"),
                "checker_detail": checked.get("detail"),
                "compiled_agrees": checked.get("compiled_agrees"),
                "compiled_conflicts": checked.get("compiled_conflicts"),
                "open_obligation_count": len(rows_by_role.get((object_id, kind), [])),
            })
            continue
        if form != "obligation":
            continue
        object_id = claim.get("object")
        coordinate = claim.get("coordinate")
        decision = claim.get("decision")
        if not all(isinstance(value, str) for value in (
            reason_id, object_id, coordinate, decision,
        )):
            raise ValueError("TIER_ZERO_REASONING_OBLIGATION_REASON_INVALID")
        if decision != "REQUIRED":
            raise ValueError("TIER_ZERO_REASONING_OBLIGATION_REASON_WEAKENS_DENOMINATOR")
        checked = check_reasons.get(reason_id, {})
        checker_status = checked.get("status")
        key = (object_id, coordinate)
        target = rows_by_key.get(key)
        accepted = checker_status in accepted_statuses
        if not accepted:
            disposition = "REJECTED_BY_CHECKER"
        elif target is None:
            disposition = "OUTSIDE_THIS_DENOMINATOR"
        elif checked.get("compiled_match") is not True:
            disposition = "CHECKER_DENOMINATOR_MISMATCH"
        else:
            disposition = "RECONCILED_WITH_OPEN_DENOMINATOR"
        candidate = {
            "reason_id": reason_id,
            "object_id": object_id,
            "coordinate": coordinate,
            "decision": decision,
            "checker_status": checker_status,
            "checker_detail": checked.get("detail"),
            "compiled_match": checked.get("compiled_match"),
            "disposition": disposition,
            "obligation": target,
        }
        candidates.append(candidate)
        by_key.setdefault(key, []).append(candidate)

    duplicate_keys: list[dict[str, Any]] = []
    for key, reasons in sorted(by_key.items()):
        if len(reasons) > 1:
            duplicate_keys.append({
                "object_id": key[0],
                "coordinate": key[1],
                "reason_ids": sorted(row["reason_id"] for row in reasons),
            })

    duplicated = {
        (row["object_id"], row["coordinate"])
        for row in duplicate_keys
    }
    reconciled_keys = {
        (row["object_id"], row["coordinate"])
        for row in candidates
        if row["disposition"] == "RECONCILED_WITH_OPEN_DENOMINATOR"
    } - duplicated
    unreasoned_keys = sorted(set(rows_by_key) - reconciled_keys)
    reasoned_rows = [rows_by_key[key] for key in sorted(reconciled_keys)]
    unreasoned_rows = [rows_by_key[key] for key in unreasoned_keys]
    rejected = [
        row["reason_id"]
        for row in candidates
        if row["disposition"] == "REJECTED_BY_CHECKER"
    ]
    mismatched = [
        row["reason_id"]
        for row in candidates
        if row["disposition"] == "CHECKER_DENOMINATOR_MISMATCH"
    ]
    outside = [
        row["reason_id"]
        for row in candidates
        if row["disposition"] == "OUTSIDE_THIS_DENOMINATOR"
    ]
    mechanism_status = (
        "FAIL"
        if duplicate_keys or mismatched
        else "UNKNOWN"
        if rejected
        else "PASS"
    )
    coverage_status = "PASS" if not unreasoned_keys else "UNKNOWN"
    reasoned_roles = {
        (row["object_id"], row["kind"])
        for row in reasoned_rows
    }
    unreasoned_roles = {
        (row["object_id"], row["kind"])
        for row in unreasoned_rows
    }
    return {
        "schema_version": "verifier-tier-zero-obligation-reason-reconciliation-2",
        "mechanism_status": mechanism_status,
        "coverage_status": coverage_status,
        "counts": {
            "open_obligations": len(open_rows),
            "open_role_pairs": len(rows_by_role),
            "open_obligation_statuses": dict(sorted(status_counts.items())),
            "classification_references": len(classification_references),
            "obligation_reasons": len(candidates),
            "reconciled_reasons": sum(
                row["disposition"] == "RECONCILED_WITH_OPEN_DENOMINATOR"
                for row in candidates
            ),
            "reasoned_role_pairs": len(reasoned_roles),
            "reasoned_obligations": len(reasoned_rows),
            "unreasoned_role_pairs": len(unreasoned_roles),
            "unreasoned_obligations": len(unreasoned_rows),
            "evidence_unresolved_obligations": status_counts.get("FAIL", 0),
            "classification_unresolved_obligations": status_counts.get("UNKNOWN", 0),
            "rejected_reasons": len(rejected),
            "checker_denominator_mismatches": len(mismatched),
            "out_of_denominator_obligation_reasons": len(outside),
            "duplicate_obligation_keys": len(duplicate_keys),
        },
        "obligation_reasons": sorted(
            candidates,
            key=lambda row: (
                row["object_id"], row["coordinate"], row["reason_id"],
            ),
        ),
        "classification_references": sorted(
            classification_references,
            key=lambda row: (row["object_id"], row["kind"], row["reason_id"]),
        ),
        "unreasoned_obligations": unreasoned_rows,
        "duplicate_obligation_keys": duplicate_keys,
        "rejected_reasons": sorted(rejected),
        "checker_denominator_mismatches": sorted(mismatched),
        "out_of_denominator_obligation_reasons": sorted(outside),
        "claim_boundary": (
            "This receipt reconciles one checked REQUIRED reason per exact compiled open "
            "obligation. It does not edit objects.vstd, supply a checker PASS, refresh source "
            "evidence, or promote any obligation status. Reasons outside this denominator "
            "remain for their owning package-polish tier to reconcile."
        ),
    }


def _reconcile_obligation_reasons(
    reasons_path: Path,
    check_path: Path,
    objects_path: Path,
    output: Path,
) -> dict[str, Any]:
    parsed = reasons_dsl.parse(
        reasons_path.read_text(encoding="utf-8"),
        reasons_path.name,
    )
    if parsed["errors"] or parsed["malformed"]:
        raise ValueError("TIER_ZERO_REASONING_RECONCILIATION_INPUT_INVALID")
    report = _reconcile_obligation_reason_documents(
        parsed["ir"],
        json.loads(check_path.read_text(encoding="utf-8")),
        json.loads(objects_path.read_text(encoding="utf-8")),
    )
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report


def assess(
    root: Path,
    reasons: Path,
    output: Path,
    *,
    witness_specs: Path | None = None,
    subject: str = "nontest",
    annotations: str = "concrete",
    implicit: str = "all",
    name_rule: str = "off",
    timeout: int = 1800,
    run_alias_gate: bool = False,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not (root / ".git").exists():
        # Linked worktrees use a .git file; a missing path is the actual refusal.
        if not (root / ".git").is_file():
            raise ValueError("TIER_ZERO_REASONING_ROOT_NOT_GIT_WORKTREE")
    objects_path = (root / "objects.vstd").resolve(strict=True)
    selected_reason = reasons.resolve(strict=True)
    if selected_reason != (root / "reasons.vstd").resolve() or selected_reason.name != "reasons.vstd":
        raise ValueError("TIER_ZERO_REASONING_REASONS_MUST_BE_ROOT_REASONS_VSTD")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    before = _source_coordinate(root)

    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
        str(root), str(root / "src"), environment.get("PYTHONPATH", ""),
    )))
    environment["REASONS_ROOT"] = str(root)
    environment["REACH_NAME_RULE"] = name_rule
    environment["REACH_IMPLICIT"] = implicit
    environment["REACH_ANNOTATIONS"] = annotations
    if subject == "whole":
        environment.pop("REACH_SUBJECT", None)
    else:
        environment["REACH_SUBJECT"] = subject
    environment["VSTD_WITNESS_BASETEMP"] = str(output / "witness-temp")

    steps: list[dict[str, Any]] = []

    # Compile the registry before evaluating developer-authored reasons.  The
    # resulting dump is the obligation denominator that reasons.vstd answers.
    projection_report = output / "effect_first_projection.json"
    dump = output / "objects_dump.json"
    projection = _step(
        "objects-registry-projection",
        [
            sys.executable, "-B", str(_HERE / "project_effect_first.py"),
            str(projection_report), str(dump),
        ],
        root=root, output=output, environment=environment, timeout=timeout,
    )
    if projection["state"] == "COMPLETED":
        try:
            projection_document = json.loads(projection_report.read_text(encoding="utf-8"))
            objects_dump = json.loads(dump.read_text(encoding="utf-8"))
            projection["result_status"] = projection_document["status"]
            projection["report"] = str(projection_report)
            projection["report_sha256"] = _digest(projection_report.read_bytes())
            projection["objects_dump"] = str(dump)
            projection["objects_dump_sha256"] = _digest(dump.read_bytes())
            projection["obligation_count"] = len(objects_dump.get("open_obligations", []))
            projection["obligation_denominator_sha256"] = _digest(
                _canonical(objects_dump.get("open_obligations", []))
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            projection["state"] = "FAILED"
            projection["exit_code"] = 1
            projection["reason"] = "projection artifacts invalid: " + type(exc).__name__
    steps.append(projection)

    replace_codec_path = output / "replace_codec_probe.json"
    replace_codec_step = _step(
        "replace-codec-probe",
        [sys.executable, "-B", str(_HERE / "replace_codec_probe.py"), str(replace_codec_path)],
        root=root,
        output=output,
        environment=environment,
        timeout=timeout,
    )
    if replace_codec_step["state"] == "COMPLETED":
        try:
            replace_codec_report = json.loads(replace_codec_path.read_text(encoding="utf-8"))
            replace_codec_step["result_status"] = replace_codec_report["status"]
            replace_codec_step["report"] = str(replace_codec_path)
            replace_codec_step["report_sha256"] = _digest(replace_codec_path.read_bytes())
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            replace_codec_step["state"] = "FAILED"
            replace_codec_step["exit_code"] = 1
            replace_codec_step["reason"] = "replace/codec receipt invalid: " + type(exc).__name__
    steps.append(replace_codec_step)

    conditional_path = output / "conditional_dispatch.json"
    conditional = conditional_dispatch.write_report(root, conditional_path)
    conditional_step = {
        "name": "conditional-dispatch",
        "state": "COMPLETED" if not conditional["source_files_changed_during_scan"] else "FAILED",
        "exit_code": 0 if not conditional["source_files_changed_during_scan"] else 1,
        "report": str(conditional_path),
        "report_sha256": _digest(conditional_path.read_bytes()),
        "counts": conditional["counts"],
    }
    steps.append(conditional_step)
    print(f"[{conditional_step['state']}] conditional-dispatch {conditional['counts']}", file=sys.stderr)

    registry_path = output / "binding_registry.json"
    if projection["state"] == "COMPLETED":
        compile_step = _step(
            "binding-registry-compile",
            [
                sys.executable, "-B", str(_HERE / "binding_registry.py"), "compile",
                "--root", str(root), "--out", str(registry_path),
                str(selected_reason),
            ],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        compile_step = _blocked("binding-registry-compile", projection["name"])
    steps.append(compile_step)

    rewritten = output / "rewritten"
    if compile_step["state"] == "COMPLETED":
        rewrite_step = _step(
            "binding-registry-rewrite",
            [
                sys.executable, "-B", str(_HERE / "binding_registry.py"), "rewrite",
                "--root", str(root), "--registry", str(registry_path), "--out-dir", str(rewritten),
                str(selected_reason),
            ],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        rewrite_step = _blocked("binding-registry-rewrite", compile_step["name"])
    steps.append(rewrite_step)

    rewritten_reason = rewritten / selected_reason.name
    check_dir = output / "reason-check"
    environment["REASONS_OBJECTS_DUMP"] = str(dump)
    if rewrite_step["state"] == "COMPLETED":
        reason_step = _step(
            "reason-check",
            [sys.executable, "-B", str(_HERE / "reasons_check.py"), str(check_dir),
             str(rewritten_reason)],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        reason_step = _blocked("reason-check", rewrite_step["name"])
    steps.append(reason_step)

    obligation_reconciliation_path = output / "obligation_reason_reconciliation.json"
    if reason_step["state"] == "COMPLETED" and projection["state"] == "COMPLETED":
        try:
            obligation_reconciliation = _reconcile_obligation_reasons(
                rewritten_reason,
                check_dir / "check.json",
                dump,
                obligation_reconciliation_path,
            )
            obligation_reconciliation_step = {
                "name": "obligation-reason-reconciliation",
                "state": "COMPLETED",
                "exit_code": 0,
                "mechanism_status": obligation_reconciliation["mechanism_status"],
                "coverage_status": obligation_reconciliation["coverage_status"],
                "counts": obligation_reconciliation["counts"],
                "report": str(obligation_reconciliation_path),
                "report_sha256": _digest(obligation_reconciliation_path.read_bytes()),
            }
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            obligation_reconciliation_step = {
                "name": "obligation-reason-reconciliation",
                "state": "FAILED",
                "exit_code": 1,
                "reason": type(exc).__name__,
            }
    else:
        dependency = (
            reason_step["name"]
            if reason_step["state"] != "COMPLETED"
            else projection["name"]
        )
        obligation_reconciliation_step = _blocked(
            "obligation-reason-reconciliation", dependency
        )
    steps.append(obligation_reconciliation_step)

    observations_path = output / "observations.json"
    if rewrite_step["state"] == "COMPLETED":
        try:
            observation_report = _observations([rewritten_reason], observations_path)
            observation_step = {
                "name": "falsifier-observations", "state": "COMPLETED", "exit_code": 0,
                "report": str(observations_path),
                "observation_count": len(observation_report["observations"]),
                "report_sha256": _digest(observations_path.read_bytes()),
            }
        except (OSError, ValueError) as exc:
            observation_step = {
                "name": "falsifier-observations", "state": "FAILED", "exit_code": 1,
                "reason": str(exc),
            }
    else:
        observation_step = _blocked("falsifier-observations", rewrite_step["name"])
    steps.append(observation_step)

    witness_output = output / "witness_receipts.json"
    if witness_specs is not None and reason_step["state"] == "COMPLETED":
        witness_step = _step(
            "witness-receipts",
            [sys.executable, "-B", str(_HERE / "witness_runner.py"),
             str(witness_specs.resolve(strict=True)), str(witness_output)],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    elif witness_specs is None:
        witness_step = {
            "name": "witness-receipts", "state": "UNKNOWN", "exit_code": None,
            "reason": "no witness specification was selected",
        }
    else:
        witness_step = _blocked("witness-receipts", reason_step["name"])
    steps.append(witness_step)

    reconciliation_path = output / "witness_reconciliation.json"
    if (
        reason_step["state"] == "COMPLETED"
        and observation_step["state"] == "COMPLETED"
        and witness_step["state"] == "COMPLETED"
    ):
        try:
            reconciliation = _reconcile_witnesses(
                check_dir / "check.json",
                observations_path,
                witness_output,
                reconciliation_path,
            )
            reconciliation_step = {
                "name": "witness-reconciliation",
                "state": "COMPLETED",
                "exit_code": 0,
                "mechanism_status": reconciliation["mechanism_status"],
                "counts": reconciliation["counts"],
                "report": str(reconciliation_path),
                "report_sha256": _digest(reconciliation_path.read_bytes()),
            }
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            reconciliation_step = {
                "name": "witness-reconciliation",
                "state": "FAILED",
                "exit_code": 1,
                "reason": type(exc).__name__,
            }
    elif witness_specs is None:
        reconciliation_step = {
            "name": "witness-reconciliation",
            "state": "UNKNOWN",
            "exit_code": None,
            "reason": "no witness specification was selected",
        }
    else:
        dependency = next(
            step["name"]
            for step in (reason_step, observation_step, witness_step)
            if step["state"] != "COMPLETED"
        )
        reconciliation_step = _blocked("witness-reconciliation", dependency)
    steps.append(reconciliation_step)

    redundancy_path = output / "redundancy_obligations.json"
    guards_path = output / "redundant_guard_census.json"
    if reason_step["state"] == "COMPLETED":
        redundancy_step = _step(
            "redundancy-obligations",
            [sys.executable, "-B", str(_HERE / "redundancy_obligations.py"), "project",
             str(redundancy_path), str(check_dir / "check.json")],
            root=root, output=output, environment=environment, timeout=timeout,
        )
        guard_step = _step(
            "redundant-guard-census",
            [sys.executable, "-B", str(_HERE / "redundancy_obligations.py"), "guards",
             str(root), str(guards_path)],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        redundancy_step = _blocked("redundancy-obligations", reason_step["name"])
        guard_step = _blocked("redundant-guard-census", reason_step["name"])
    steps.extend((redundancy_step, guard_step))

    reach_path = output / "effect_reach.json"
    facts_path = check_dir / "facts_documented.json"
    if reason_step["state"] == "COMPLETED":
        environment["REACH_FACTS"] = str(facts_path)
        reach_step = _step(
            "followed-effect-reach",
            [sys.executable, "-B", str(_HERE / "effect_reach_prototype.py"), str(dump), str(reach_path)],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        reach_step = _blocked("followed-effect-reach", reason_step["name"])
    steps.append(reach_step)

    if run_alias_gate:
        alias_step = _step(
            "alias-hole-focused-gate",
            [sys.executable, "-B", "-m", "pytest", "-q",
             "tests/test_package_original_kind_review_alias_hole.py"],
            root=root, output=output, environment=environment, timeout=timeout,
        )
    else:
        alias_step = {
            "name": "alias-hole-focused-gate", "state": "NOT_REQUESTED", "exit_code": None,
            "reason": "run with --alias-gate to execute the focused alias cases",
        }
    steps.append(alias_step)

    after = _source_coordinate(root)
    source_unchanged = before == after
    required_states = [step["state"] for step in steps if step["name"] != "alias-hole-focused-gate"]
    if not source_unchanged or any(state in {"FAILED", "TIMED_OUT", "BLOCKED"} for state in required_states):
        status = "FAIL"
    elif replace_codec_step.get("result_status") != "PASS":
        status = "FAIL"
    elif obligation_reconciliation_step.get("mechanism_status") == "FAIL":
        status = "FAIL"
    elif projection.get("result_status") == "UNKNOWN":
        status = "UNKNOWN"
    elif obligation_reconciliation_step.get("mechanism_status") != "PASS":
        status = "UNKNOWN"
    elif obligation_reconciliation_step.get("coverage_status") != "PASS":
        status = "UNKNOWN"
    elif witness_step["state"] != "COMPLETED":
        status = "UNKNOWN"
    elif reconciliation_step.get("mechanism_status") != "PASS":
        status = "UNKNOWN"
    elif run_alias_gate and alias_step["state"] != "COMPLETED":
        status = "FAIL"
    else:
        status = "PASS"
    receipt: dict[str, Any] = {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": status,
        "root": str(root),
        "output": str(output),
        "coordinate_before": before,
        "coordinate_after": after,
        "source_unchanged_during_assessment": source_unchanged,
        "configuration": {
            "subject": subject, "annotations": annotations, "implicit": implicit,
            "name_rule": name_rule, "witness_specs": str(witness_specs) if witness_specs else None,
            "alias_gate": run_alias_gate,
        },
        "inputs": {
            "objects_vstd": str(objects_path),
            "objects_vstd_sha256": _digest(objects_path.read_bytes()),
            "reasons_vstd": str(selected_reason),
            "reasons_vstd_sha256": _digest(selected_reason.read_bytes()),
            "obligation_count": projection.get("obligation_count"),
            "obligation_denominator_sha256": projection.get(
                "obligation_denominator_sha256"
            ),
        },
        "steps": steps,
        "time_status": "OPEN",
        "claim_boundary": (
            "PASS establishes only that the integrated Tier-zero reason mechanisms completed against one "
            "unchanged source coordinate. It does not resolve TIME.md, adopt proposed decisions, establish "
            "package polish, authorize pin refresh, or establish release or deployment readiness."
        ),
    }
    body = _canonical(receipt)
    receipt["receipt_digest"] = _digest(body)
    receipt_path = output / "assessment.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return receipt


__all__ = [
    "ROOT_REASON_AUTHORITY_SCHEMA",
    "RootReasonSelection",
    "assess",
    "documented_applicability_answers",
    "select_root_reasons",
]
