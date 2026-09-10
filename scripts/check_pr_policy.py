#!/usr/bin/env python3
"""Terminology: continuous integration (CI); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
uniform resource locator (URL); Verifier Standard (VSTD).

Validate the exact-head pull-request promotion record.

The check proves only that required evidence is complete and that a trusted
repository participant accepted its exact record digest and head. It cannot
prove comprehension, correctness, independence, merge authority, or release authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET


FIELD_NAMES = (
    "Final head commit",
    "Final base commit",
    "Executed integration commit",
    "Repository-check event",
    "Repository-check run",
    "Promotion record SHA-256",
    "Actionable findings",
    "Tests skipped or not run",
    "Human acceptance evidence",
    "Post-merge validation owner and surfaces",
)
BOUND_FIELD_NAMES = tuple(
    name
    for name in FIELD_NAMES
    if name not in {"Promotion record SHA-256", "Human acceptance evidence"}
)
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
REPOSITORY_CHECK_WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_CHECKLIST_ITEMS = (
    "I did not turn `UNKNOWN` or `CONFLICTED` into a clean result.",
    "I did not strengthen a claim without stronger evidence.",
    "I did not include secrets, private data, or proprietary operational material.",
    "Normative text, machine-readable surfaces, examples, and tests agree.",
    "README maturity, claims guidance, generated reference, and Pages status still agree.",
    "Every actionable review finding is resolved or explicitly retained as a blocker.",
    "The promotion record and human acceptance bind the current final head.",
    "Hosted and local evidence was refreshed after the final push.",
    "Every skipped or unrun check and its claim consequence is disclosed.",
    "Post-merge validation has a named owner; merge and release remain separately authorized actions.",
)
PLACEHOLDER = re.compile(
    r"(?:\bTBD\b|\bTODO\b|\bPENDING\b|REPLACE|FULL[_ -]?SHA|PR[_ -]?URL)",
    re.IGNORECASE,
)
ACCEPTANCE_MARKER = re.compile(
    r"^VSTD-HUMAN-ACCEPTANCE:\s*([0-9a-f]{40})\s+([0-9a-f]{64})\s*$",
    re.MULTILINE,
)
GATE_DISPOSITION = re.compile(r"^- \[(ACCEPTED|NOT APPLICABLE)\] .+", re.IGNORECASE)
TEST_DISPOSITION = re.compile(
    r"^(NONE|DISCLOSED) — test-evidence-sha256=([0-9a-f]{64}) — "
    r"total-skipped=(0|[1-9][0-9]*); "
    r"skip-observation-omissions=(NONE|[a-z0-9-]+(?:,[a-z0-9-]+)*)$",
)
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
FULL_DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_BODY_BYTES = 256 * 1024
MAX_RECORDS = 99
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_SKIP_REASON_CHARACTERS = 4096
TEST_EVIDENCE_CLAIM_BOUNDARY = (
    "Inventory of the eleven expected hosted pytest reports for this repository-check run; "
    "it records bounded skip observations from every pytest invocation in that workflow but "
    "does not establish that passing tests prove correctness or completeness."
)
SKIP_OBSERVATION_OMISSIONS: tuple[str, ...] = ()
EXPECTED_REPORTS = (
    ("base", "python-3.10", "base-contracts.xml"),
    ("base", "python-3.11", "base-contracts.xml"),
    ("base", "python-3.12", "base-contracts.xml"),
    ("base", "python-3.13", "base-contracts.xml"),
    ("platform", "linux-x64", "platform-contracts.xml"),
    ("platform", "windows-x64", "platform-contracts.xml"),
    ("platform", "macos-x64", "platform-contracts.xml"),
    ("platform", "macos-arm64", "platform-contracts.xml"),
    ("coverage", "python-3.12", "coverage-tests.xml"),
    ("scitt-crypto", "python-3.12", "scitt-crypto.xml"),
    ("artifact-seal", "python-3.12", "artifact-seal.xml"),
)
REPORT_ARTIFACT_PREFIXES = {
    "artifact-seal": "artifact-seal",
    "base": "base-contracts",
    "coverage": "coverage-tests",
    "platform": "platform-python-contracts",
    "scitt-crypto": "scitt-crypto",
}


class PullRequestPolicyError(ValueError):
    """Raised when a pull request lacks exact promotion evidence."""


def _load_json(path: Path) -> Any:
    with path.open("rb") as stream:
        payload = stream.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise PullRequestPolicyError("policy evidence exceeds the JSON byte limit")
    return json.loads(payload.decode("utf-8"))


def _records(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, list):
        raise PullRequestPolicyError("review evidence must be a JSON array")
    flattened: list[dict[str, Any]] = []
    for item in document:
        if isinstance(item, list):
            for record in item:
                if not isinstance(record, dict):
                    raise PullRequestPolicyError("review evidence contains a non-object record")
                flattened.append(record)
        elif isinstance(item, dict):
            flattened.append(item)
        else:
            raise PullRequestPolicyError("review evidence contains a non-object record")
        if len(flattened) > MAX_RECORDS:
            raise PullRequestPolicyError("review evidence exceeds the conservative record limit")
    return flattened


def _bounded_body(body: str) -> str:
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise PullRequestPolicyError("pull-request body exceeds the byte limit")
    return body


def _pull_request(document: dict[str, Any]) -> dict[str, Any]:
    pull_request = document.get("pull_request")
    if pull_request is None and all(key in document for key in ("body", "head", "base")):
        pull_request = document
    if not isinstance(pull_request, dict):
        raise PullRequestPolicyError("event has no pull_request object")
    return pull_request


def _field(body: str, name: str) -> str:
    matches = list(
        re.finditer(rf"^- {re.escape(name)}:\s*(.+?)\s*$", body, re.MULTILINE)
    )
    if not matches:
        raise PullRequestPolicyError(f"missing promotion field: {name}")
    if len(matches) != 1:
        raise PullRequestPolicyError(
            f"promotion field must occur exactly once: {name}"
        )
    match = matches[0]
    value = match.group(1).strip()
    if not value or PLACEHOLDER.search(value):
        raise PullRequestPolicyError(f"promotion field is unresolved: {name}")
    return value


def _section(body: str, heading: str) -> str:
    headings = list(
        re.finditer(rf"^## {re.escape(heading)}\s*$", body, re.MULTILINE)
    )
    if not headings:
        raise PullRequestPolicyError(f"missing or empty section: {heading}")
    if len(headings) != 1:
        raise PullRequestPolicyError(f"section must occur exactly once: {heading}")
    start = headings[0].end()
    next_heading = re.search(r"^## ", body[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading is not None else len(body)
    value = body[start:end].strip()
    if not value:
        raise PullRequestPolicyError(f"missing or empty section: {heading}")
    if PLACEHOLDER.search(value):
        raise PullRequestPolicyError(f"section is unresolved: {heading}")
    return value


def _human_gates(body: str) -> list[str]:
    lines = [
        line.strip()
        for line in _section(body, "Human review gates").splitlines()
        if line.strip()
    ]
    if not lines or any(GATE_DISPOSITION.fullmatch(line) is None for line in lines):
        raise PullRequestPolicyError(
            "every human review gate must have an explicit ACCEPTED or NOT APPLICABLE disposition"
        )
    return lines


def _checklist(body: str) -> list[str]:
    lines = [
        line.strip()
        for line in _section(body, "Checklist").splitlines()
        if line.strip()
    ]
    if len(lines) != len(REQUIRED_CHECKLIST_ITEMS) or any(
        line not in {f"- [x] {item}", f"- [X] {item}"}
        for line, item in zip(lines, REQUIRED_CHECKLIST_ITEMS)
    ):
        raise PullRequestPolicyError(
            "checklist must contain every required item exactly once and checked"
        )
    return lines


def promotion_record(body: str) -> dict[str, object]:
    """Return the canonical non-circular record bound by human acceptance."""
    body = _bounded_body(body)
    promotion_section = _section(body, "Promotion record")
    values = {name: _field(body, name) for name in BOUND_FIELD_NAMES}
    for name, value in values.items():
        if _field(promotion_section, name) != value:
            raise PullRequestPolicyError(f"promotion field is outside its section: {name}")
    return {
        "actionable_findings": values["Actionable findings"],
        "executed_integration_commit": values["Executed integration commit"].strip("`"),
        "final_base_commit": values["Final base commit"].strip("`"),
        "final_head_commit": values["Final head commit"].strip("`"),
        "human_review_gates": _human_gates(body),
        "required_checklist": _checklist(body),
        "post_merge_validation_owner_and_surfaces": values[
            "Post-merge validation owner and surfaces"
        ],
        "repository_check_event": values["Repository-check event"],
        "repository_check_run": values["Repository-check run"],
        "tests_skipped_or_not_run": values["Tests skipped or not run"],
    }


def promotion_record_sha256(body: str) -> str:
    canonical = json.dumps(
        promotion_record(body),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_json_sha256(document: Any) -> str:
    canonical = json.dumps(
        document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_test_evidence_manifest(root: Path, run_id: str, run_attempt: str) -> dict[str, Any]:
    """Build a bounded manifest from the exact expected hosted pytest reports."""
    if re.fullmatch(r"[1-9][0-9]*", run_id) is None or re.fullmatch(
        r"[1-9][0-9]*", run_attempt
    ) is None:
        raise PullRequestPolicyError("test-evidence run coordinates must be positive IDs")
    reports: list[dict[str, Any]] = []
    expected_artifact_names: set[str] = set()
    for kind, coordinate, filename in EXPECTED_REPORTS:
        prefix = REPORT_ARTIFACT_PREFIXES[kind]
        artifact = root / f"{prefix}-{run_id}-{run_attempt}-{coordinate}"
        expected_artifact_names.add(artifact.name)
        path = artifact / filename
        if not path.is_file():
            raise PullRequestPolicyError(
                f"missing expected test-evidence artifact: {artifact.name}/{filename}"
            )
        payload = path.read_bytes()
        if len(payload) > MAX_REPORT_BYTES:
            raise PullRequestPolicyError(f"test report exceeds byte limit: {artifact.name}")
        if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
            raise PullRequestPolicyError(f"unsafe XML declaration in: {artifact.name}")
        try:
            xml_root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise PullRequestPolicyError(f"invalid JUnit XML in: {artifact.name}") from exc
        cases = list(xml_root.iter("testcase"))
        skips: list[dict[str, str]] = []
        failures = 0
        errors = 0
        for case in cases:
            test_name = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
            if not test_name:
                raise PullRequestPolicyError(f"unnamed test case in: {artifact.name}")
            skipped = case.find("skipped")
            if skipped is not None:
                reason = (skipped.get("message") or skipped.text or "").strip()
                if not reason:
                    raise PullRequestPolicyError(
                        f"skipped test has no reason: {artifact.name}/{test_name}"
                    )
                if len(reason) > MAX_SKIP_REASON_CHARACTERS:
                    raise PullRequestPolicyError(
                        f"skipped test reason exceeds {MAX_SKIP_REASON_CHARACTERS} characters: "
                        f"{artifact.name}/{test_name}"
                    )
                skips.append(
                    {"test": test_name, "reason": reason}
                )
            failures += int(case.find("failure") is not None)
            errors += int(case.find("error") is not None)
        reports.append(
            {
                "coordinate": coordinate,
                "errors": errors,
                "failures": failures,
                "kind": kind,
                "report_sha256": hashlib.sha256(payload).hexdigest(),
                "skipped": len(skips),
                "skips": sorted(skips, key=lambda item: (item["test"], item["reason"])),
                "tests": len(cases),
            }
        )
    unexpected_artifacts = sorted(
        path.name for path in root.iterdir() if path.name not in expected_artifact_names
    )
    if unexpected_artifacts:
        raise PullRequestPolicyError(
            "unexpected test-evidence artifact: " + ", ".join(unexpected_artifacts)
        )
    return {
        "claim_boundary": TEST_EVIDENCE_CLAIM_BOUNDARY,
        "expected_report_omissions": [],
        "reports": reports,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "schema_version": 1,
        "skip_observation_omissions": list(SKIP_OBSERVATION_OMISSIONS),
        "total_skipped": sum(report["skipped"] for report in reports),
        "total_tests": sum(report["tests"] for report in reports),
    }


def _validate_test_evidence_manifest(
    document: dict[str, Any], *, run_id: str, run_attempt: str
) -> tuple[str, int, int]:
    expected_keys = {
        "claim_boundary", "expected_report_omissions", "reports", "run_attempt",
        "run_id", "schema_version", "skip_observation_omissions", "total_skipped",
        "total_tests",
    }
    if set(document) != expected_keys or document.get("schema_version") != 1:
        raise PullRequestPolicyError("test-evidence manifest schema is not exact")
    if document.get("claim_boundary") != TEST_EVIDENCE_CLAIM_BOUNDARY:
        raise PullRequestPolicyError("test-evidence manifest claim boundary is not exact")
    if document.get("run_id") != run_id or document.get("run_attempt") != run_attempt:
        raise PullRequestPolicyError("test-evidence manifest run coordinate does not match")
    if document.get("expected_report_omissions") != []:
        raise PullRequestPolicyError("test-evidence manifest has expected report omissions")
    if document.get("skip_observation_omissions") != list(SKIP_OBSERVATION_OMISSIONS):
        raise PullRequestPolicyError("test-evidence skip-observation omissions are not exact")
    reports = document.get("reports")
    if not isinstance(reports, list) or len(reports) != len(EXPECTED_REPORTS):
        raise PullRequestPolicyError("test-evidence manifest report inventory is incomplete")
    expected_coordinates = [(kind, coordinate) for kind, coordinate, _ in EXPECTED_REPORTS]
    observed_coordinates: list[tuple[str, str]] = []
    total_tests = 0
    total_skipped = 0
    for report in reports:
        if not isinstance(report, dict) or set(report) != {
            "coordinate", "errors", "failures", "kind", "report_sha256", "skipped",
            "skips", "tests",
        }:
            raise PullRequestPolicyError("test-evidence report schema is not exact")
        observed_coordinates.append((report.get("kind"), report.get("coordinate")))
        digest = report.get("report_sha256")
        counts = [report.get(name) for name in ("tests", "skipped", "failures", "errors")]
        skips = report.get("skips")
        if (
            not isinstance(digest, str) or FULL_DIGEST.fullmatch(digest) is None
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts)
            or not isinstance(skips, list) or len(skips) != report.get("skipped")
            or report.get("skipped") > report.get("tests")
            or report.get("failures") != 0 or report.get("errors") != 0
        ):
            raise PullRequestPolicyError("test-evidence report values are invalid")
        for skip in skips:
            if (
                not isinstance(skip, dict)
                or set(skip) != {"test", "reason"}
                or not isinstance(skip["test"], str)
                or not skip["test"]
                or not isinstance(skip["reason"], str)
                or not skip["reason"].strip()
                or len(skip["reason"]) > MAX_SKIP_REASON_CHARACTERS
            ):
                raise PullRequestPolicyError("test-evidence skip record is invalid")
        total_tests += report["tests"]
        total_skipped += report["skipped"]
    if observed_coordinates != expected_coordinates:
        raise PullRequestPolicyError("test-evidence manifest coordinates are not canonical")
    if document.get("total_tests") != total_tests or document.get("total_skipped") != total_skipped:
        raise PullRequestPolicyError("test-evidence manifest totals do not reconcile")
    return _canonical_json_sha256(document), total_tests, total_skipped


def _acceptance_url(value: str) -> str:
    match = re.search(r"https://github\.com/[^\s)>]+", value)
    if match is None:
        raise PullRequestPolicyError(
            "Human acceptance evidence must link to a GitHub review or comment"
        )
    return match.group(0).rstrip(".,")


def _trusted_acceptance(
    *,
    url: str,
    head_sha: str,
    record_sha256: str,
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
) -> bool:
    latest_by_reviewer: dict[str, dict[str, Any]] = {}
    seen_review_ids: set[int] = set()
    for review in reviews:
        if review.get("author_association") not in TRUSTED_ASSOCIATIONS:
            continue
        state = review.get("state")
        if state not in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            continue
        user = review.get("user")
        review_id = review.get("id")
        if not isinstance(user, dict) or not isinstance(user.get("login"), str) or not user["login"]:
            raise PullRequestPolicyError("trusted review has no reviewer identity")
        if not isinstance(review_id, int) or isinstance(review_id, bool) or review_id <= 0 or review_id in seen_review_ids:
            raise PullRequestPolicyError("trusted review has an invalid or duplicate ID")
        seen_review_ids.add(review_id)
        current = latest_by_reviewer.get(user["login"])
        if current is None or review_id > current["id"]:
            latest_by_reviewer[user["login"]] = review
    if any(review.get("state") == "CHANGES_REQUESTED" for review in latest_by_reviewer.values()):
        raise PullRequestPolicyError("a trusted reviewer's current state requests changes")
    for review in latest_by_reviewer.values():
        marker = ACCEPTANCE_MARKER.search(str(review.get("body", "")))
        if (
            review.get("html_url") == url
            and review.get("state") == "APPROVED"
            and review.get("commit_id") == head_sha
            and review.get("author_association") in TRUSTED_ASSOCIATIONS
            and marker is not None
            and marker.groups() == (head_sha, record_sha256)
        ):
            return True
    for comment in comments:
        marker = ACCEPTANCE_MARKER.search(str(comment.get("body", "")))
        if (
            comment.get("html_url") == url
            and comment.get("author_association") in TRUSTED_ASSOCIATIONS
            and marker is not None
            and marker.groups() == (head_sha, record_sha256)
        ):
            return True
    return False


def validate(
    event: dict[str, Any],
    *,
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    ci_coordinate: dict[str, Any],
    repository_run: dict[str, Any],
    test_evidence_manifest: dict[str, Any],
) -> dict[str, Any]:
    pull_request = _pull_request(event)
    body = pull_request.get("body")
    head = pull_request.get("head")
    base = pull_request.get("base")
    if not isinstance(body, str) or not isinstance(head, dict) or not isinstance(base, dict):
        raise PullRequestPolicyError("pull-request body or coordinates are unavailable")
    body = _bounded_body(body)
    head_sha = head.get("sha")
    base_sha = base.get("sha")
    if not isinstance(head_sha, str) or FULL_COMMIT.fullmatch(head_sha) is None:
        raise PullRequestPolicyError("pull-request head SHA is not a full lowercase commit ID")
    if not isinstance(base_sha, str) or FULL_COMMIT.fullmatch(base_sha) is None:
        raise PullRequestPolicyError("pull-request base SHA is not a full lowercase commit ID")

    promotion_section = _section(body, "Promotion record")
    values = {name: _field(body, name) for name in FIELD_NAMES}
    for name, value in values.items():
        if _field(promotion_section, name) != value:
            raise PullRequestPolicyError(f"promotion field is outside its section: {name}")
    if not values["Actionable findings"].upper().startswith("CLEAR —"):
        raise PullRequestPolicyError("actionable findings must have a CLEAR disposition")
    disposition = TEST_DISPOSITION.fullmatch(values["Tests skipped or not run"])
    if disposition is None:
        raise PullRequestPolicyError(
            "skipped or unrun tests must have a NONE or DISCLOSED disposition and manifest digest"
        )
    if not values["Post-merge validation owner and surfaces"].upper().startswith(
        "ASSIGNED —"
    ):
        raise PullRequestPolicyError("post-merge validation must have an ASSIGNED owner")

    recorded_head = values["Final head commit"].strip("`")
    recorded_base = values["Final base commit"].strip("`")
    executed = values["Executed integration commit"].strip("`")
    if recorded_head != head_sha:
        raise PullRequestPolicyError("promotion record head does not equal current head")
    if recorded_base != base_sha:
        raise PullRequestPolicyError("promotion record base does not equal current base")
    if FULL_COMMIT.fullmatch(executed) is None:
        raise PullRequestPolicyError("executed integration commit is not a full commit ID")

    event_kind = values["Repository-check event"]
    run_id = values["Repository-check run"]
    if event_kind != "pull_request":
        raise PullRequestPolicyError("repository-check event must be pull_request")
    if re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        raise PullRequestPolicyError("repository-check run must be a positive numeric ID")
    expected_coordinate = {
        "schema_version": "1",
        "event_name": event_kind,
        "executed_coordinate_kind": "pull_request_integration",
        "executed_commit": executed,
        "pull_request_head_commit": head_sha,
        "pull_request_base_commit": base_sha,
        "run_id": run_id,
    }
    for name, expected in expected_coordinate.items():
        if str(ci_coordinate.get(name)) != expected:
            raise PullRequestPolicyError(f"CI coordinate {name} does not match promotion record")
    try:
        run_attempt_matches = int(repository_run.get("run_attempt", 0)) == int(
            ci_coordinate.get("run_attempt", -1)
        )
    except (TypeError, ValueError):
        run_attempt_matches = False
    if (
        str(repository_run.get("id")) != run_id
        or repository_run.get("name") != "repository-checks"
        or repository_run.get("path") != REPOSITORY_CHECK_WORKFLOW_PATH
        or repository_run.get("event") != event_kind
        or repository_run.get("head_sha") != head_sha
        or repository_run.get("status") != "completed"
        or repository_run.get("conclusion") != "success"
        or not run_attempt_matches
    ):
        raise PullRequestPolicyError("repository-check run is not the recorded successful run")
    manifest_digest, total_tests, total_skipped = _validate_test_evidence_manifest(
        test_evidence_manifest,
        run_id=run_id,
        run_attempt=str(ci_coordinate.get("run_attempt")),
    )
    if disposition.group(2) != manifest_digest:
        raise PullRequestPolicyError("test-evidence manifest SHA-256 does not match promotion record")
    declared_skipped = int(disposition.group(3))
    declared_omissions = (
        [] if disposition.group(4) == "NONE" else disposition.group(4).split(",")
    )
    recorded_omissions = test_evidence_manifest["skip_observation_omissions"]
    if declared_skipped != total_skipped or declared_omissions != recorded_omissions:
        raise PullRequestPolicyError(
            "test disposition summary contradicts the bound test-evidence manifest"
        )
    if disposition.group(1) == "NONE" and (
        total_skipped != 0 or recorded_omissions
    ):
        raise PullRequestPolicyError("NONE test disposition contradicts recorded skips or omissions")
    if disposition.group(1) == "DISCLOSED" and total_skipped == 0 and not recorded_omissions:
        raise PullRequestPolicyError("DISCLOSED test disposition contradicts an empty manifest")

    human_gates = _human_gates(body)
    record_sha256 = promotion_record_sha256(body)
    recorded_digest = values["Promotion record SHA-256"].strip("`")
    if FULL_DIGEST.fullmatch(recorded_digest) is None or recorded_digest != record_sha256:
        raise PullRequestPolicyError("promotion record SHA-256 does not match canonical record")
    if re.search(r"^- \[ \]", body, re.MULTILINE):
        raise PullRequestPolicyError("the pull-request checklist contains unchecked items")

    acceptance_url = _acceptance_url(values["Human acceptance evidence"])
    if not _trusted_acceptance(
        url=acceptance_url,
        head_sha=head_sha,
        record_sha256=record_sha256,
        reviews=reviews,
        comments=comments,
    ):
        raise PullRequestPolicyError(
            "acceptance evidence is not trusted or does not bind the exact head and record"
        )
    return {
        "schema_version": 1,
        "result": "PASS",
        "pull_request_number": pull_request.get("number") or event.get("number"),
        "head_sha": head_sha,
        "base_sha": base_sha,
        "executed_integration_commit": executed,
        "repository_check_event": event_kind,
        "repository_check_run": run_id,
        "promotion_record_sha256": record_sha256,
        "pull_request_body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "acceptance_url": acceptance_url,
        "human_gate_count": len(human_gates),
        "test_evidence_manifest_sha256": manifest_digest,
        "test_evidence_total_tests": total_tests,
        "test_evidence_total_skipped": total_skipped,
        "test_evidence_skip_observation_omission_count": len(
            test_evidence_manifest["skip_observation_omissions"]
        ),
        "claim_boundary": (
            "Recorded trusted-participant acceptance and coordinate completeness; not reviewer "
            "comprehension, implementation correctness, merge identity, or release authorization."
        ),
    }


def confirm_current_snapshot(
    receipt: dict[str, Any], current_event: dict[str, Any]
) -> None:
    """Reject a head, base, or body change after the acceptance evaluation."""
    pull_request = _pull_request(current_event)
    head = pull_request.get("head")
    base = pull_request.get("base")
    body = pull_request.get("body")
    if not isinstance(head, dict) or not isinstance(base, dict) or not isinstance(body, str):
        raise PullRequestPolicyError("current pull-request coordinates are unavailable")
    body = _bounded_body(body)
    body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if (
        head.get("sha") != receipt.get("head_sha")
        or base.get("sha") != receipt.get("base_sha")
        or body_sha256 != receipt.get("pull_request_body_sha256")
    ):
        raise PullRequestPolicyError(
            "pull-request head, base, or body changed during policy evaluation"
        )


def confirm_current_evidence(
    receipt: dict[str, Any], current_event: dict[str, Any], *, reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]], ci_coordinate: dict[str, Any],
    repository_run: dict[str, Any], test_evidence_manifest: dict[str, Any]
) -> None:
    """Recompute the complete policy receipt from freshly fetched mutable evidence."""
    current = validate(
        current_event, reviews=reviews, comments=comments, ci_coordinate=ci_coordinate,
        repository_run=repository_run, test_evidence_manifest=test_evidence_manifest,
    )
    if current != receipt:
        raise PullRequestPolicyError("promotion evidence changed during policy evaluation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path)
    parser.add_argument("--reviews", type=Path)
    parser.add_argument("--comments", type=Path)
    parser.add_argument("--ci-coordinate", type=Path)
    parser.add_argument("--repository-run", type=Path)
    parser.add_argument("--test-evidence-manifest", type=Path)
    parser.add_argument("--build-test-evidence-manifest", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--confirm-current", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--print-record-sha256", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.build_test_evidence_manifest is not None:
            if args.run_id is None or args.run_attempt is None or args.output is None:
                raise PullRequestPolicyError("manifest build requires run ID, attempt, and output")
            result = build_test_evidence_manifest(
                args.build_test_evidence_manifest, args.run_id, args.run_attempt
            )
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            print(_canonical_json_sha256(result))
            return 0
        if args.print_record_sha256 is not None:
            document = _load_json(args.print_record_sha256)
            print(promotion_record_sha256(str(_pull_request(document).get("body", ""))))
            return 0
        if args.confirm_current is not None or args.receipt is not None:
            if args.confirm_current is None or args.receipt is None:
                raise PullRequestPolicyError(
                    "--confirm-current and --receipt must be supplied together"
                )
            confirm_paths = (
                args.reviews, args.comments, args.ci_coordinate, args.repository_run,
                args.test_evidence_manifest,
            )
            if any(path is None for path in confirm_paths):
                raise PullRequestPolicyError("complete current promotion evidence is required")
            confirm_current_evidence(
                _load_json(args.receipt), _load_json(args.confirm_current),
                reviews=_records(_load_json(args.reviews)),
                comments=_records(_load_json(args.comments)),
                ci_coordinate=_load_json(args.ci_coordinate),
                repository_run=_load_json(args.repository_run),
                test_evidence_manifest=_load_json(args.test_evidence_manifest),
            )
            print("[PR POLICY PASS] complete current promotion evidence still matches")
            return 0
        paths = (
            args.event,
            args.reviews,
            args.comments,
            args.ci_coordinate,
            args.repository_run,
            args.test_evidence_manifest,
        )
        if any(path is None for path in paths):
            raise PullRequestPolicyError("all promotion-evidence paths are required")
        result = validate(
            _load_json(args.event),
            reviews=_records(_load_json(args.reviews)),
            comments=_records(_load_json(args.comments)),
            ci_coordinate=_load_json(args.ci_coordinate),
            repository_run=_load_json(args.repository_run),
            test_evidence_manifest=_load_json(args.test_evidence_manifest),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, PullRequestPolicyError) as exc:
        print(f"[PR POLICY FAIL] {exc}")
        return 1
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print("[PR POLICY PASS] exact-head promotion record and acceptance are bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
