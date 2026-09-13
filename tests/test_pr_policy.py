"""Terminology: continuous integration (CI); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
uniform resource locator (URL);
Verifier Standard (VSTD).

Tests for exact-head pull-request policy evidence.
"""

from __future__ import annotations

import importlib.util
from functools import lru_cache
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_pr_policy.py"
HEAD = "a" * 40
BASE = "b" * 40
INTEGRATION = "c" * 40
RUN_ID = "123"
ACCEPTANCE_URL = "https://github.com/TimeLordRaps/verifier/pull/34#issuecomment-1"


@lru_cache(maxsize=1)
def _module():
    spec = importlib.util.spec_from_file_location("check_pr_policy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(*, skipped: int = 1) -> dict[str, object]:
    reports = []
    for index, (kind, coordinate, _) in enumerate(_module().EXPECTED_REPORTS):
        count = skipped if index == 0 else 0
        reports.append(
            {
                "coordinate": coordinate,
                "errors": 0,
                "failures": 0,
                "kind": kind,
                "report_sha256": f"{index + 1:064x}",
                "skipped": count,
                "skips": ([{"test": "tests.test_example::test_skip", "reason": "bounded"}] if count else []),
                "tests": 2,
            }
        )
    return {
        "claim_boundary": _module().TEST_EVIDENCE_CLAIM_BOUNDARY,
        "expected_report_omissions": [],
        "reports": reports,
        "run_attempt": "2",
        "run_id": RUN_ID,
        "schema_version": 1,
        "skip_observation_omissions": list(_module().SKIP_OBSERVATION_OMISSIONS),
        "total_skipped": skipped,
        "total_tests": 2 * len(reports),
    }


def _body_template(*, head: str = HEAD, base: str = BASE, manifest: dict[str, object] | None = None, disposition: str = "DISCLOSED") -> str:
    evidence = manifest if manifest is not None else _manifest()
    evidence_digest = _module()._canonical_json_sha256(evidence)
    omissions = evidence["skip_observation_omissions"]
    omission_summary = ",".join(omissions) if omissions else "NONE"
    return f"""## Promotion record

- Final head commit: `{head}`
- Final base commit: `{base}`
- Executed integration commit: `{INTEGRATION}`
- Repository-check event: pull_request
- Repository-check run: {RUN_ID}
- Promotion record SHA-256: `{'0' * 64}`
- Actionable findings: CLEAR — All findings resolved in review threads.
- Tests skipped or not run: {disposition} — test-evidence-sha256={evidence_digest} — total-skipped={evidence['total_skipped']}; skip-observation-omissions={omission_summary}
- Human acceptance evidence: {ACCEPTANCE_URL}
- Post-merge validation owner and surfaces: ASSIGNED — @TimeLordRaps; checks and Pages.

## Human review gates

- [ACCEPTED] Newcomer clarity without weakened maturity or claim boundaries — accepted.
- [ACCEPTED] Bounded advisory disposition — accepted.

## Checklist

{chr(10).join(f'- [x] {item}' for item in _module().REQUIRED_CHECKLIST_ITEMS)}
"""


def _body(*, head: str = HEAD, base: str = BASE, manifest: dict[str, object] | None = None, disposition: str = "DISCLOSED") -> str:
    module = _module()
    template = _body_template(head=head, base=base, manifest=manifest, disposition=disposition)
    digest = module.promotion_record_sha256(template)
    return template.replace("0" * 64, digest)


def _event(body: str, *, head: str = HEAD, base: str = BASE) -> dict[str, object]:
    return {
        "number": 34,
        "pull_request": {
            "number": 34,
            "body": body,
            "head": {"sha": head},
            "base": {"sha": base},
        },
    }


def _coordinate() -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_name": "pull_request",
        "executed_coordinate_kind": "pull_request_integration",
        "executed_commit": INTEGRATION,
        "pull_request_head_commit": HEAD,
        "pull_request_base_commit": BASE,
        "run_id": RUN_ID,
        "run_attempt": "2",
    }


def _run() -> dict[str, object]:
    return {
        "id": int(RUN_ID),
        "name": "repository-checks",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "head_sha": HEAD,
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 2,
    }


def _comment(body: str, *, association: str = "OWNER") -> dict[str, object]:
    digest = _module().promotion_record_sha256(body)
    return {
        "html_url": ACCEPTANCE_URL,
        "author_association": association,
        "user": {"login": "maintainer"},
        "body": f"VSTD-HUMAN-ACCEPTANCE: {HEAD} {digest}",
    }


def _validate(body: str, *, comments: list[dict[str, object]] | None = None, reviews: list[dict[str, object]] | None = None, manifest: dict[str, object] | None = None):
    return _module().validate(
        _event(body),
        reviews=reviews or [],
        comments=comments if comments is not None else [_comment(body)],
        ci_coordinate=_coordinate(),
        repository_run=_run(),
        test_evidence_manifest=manifest if manifest is not None else _manifest(),
    )


def test_policy_accepts_complete_exact_coordinate_record() -> None:
    result = _validate(_body())
    assert result["result"] == "PASS"
    assert result["head_sha"] == HEAD
    assert result["base_sha"] == BASE
    assert result["executed_integration_commit"] == INTEGRATION
    assert result["repository_check_run"] == RUN_ID
    assert "not reviewer comprehension" in result["claim_boundary"]


def test_repository_check_run_from_same_named_wrong_workflow_is_rejected() -> None:
    run = _run()
    run["path"] = ".github/workflows/not-ci.yml"
    body = _body()
    with pytest.raises(_module().PullRequestPolicyError, match="recorded successful run"):
        _module().validate(
            _event(body),
            reviews=[],
            comments=[_comment(body)],
            ci_coordinate=_coordinate(),
            repository_run=run,
            test_evidence_manifest=_manifest(),
        )


def test_policy_rejects_deleted_or_reordered_required_checklist_items() -> None:
    body = _body()
    deleted = body.replace(
        f"- [x] {_module().REQUIRED_CHECKLIST_ITEMS[0]}\n", "", 1
    )
    with pytest.raises(_module().PullRequestPolicyError, match="every required item"):
        _validate(deleted)

    first, second = _module().REQUIRED_CHECKLIST_ITEMS[:2]
    reordered = body.replace(
        f"- [x] {first}\n- [x] {second}",
        f"- [x] {second}\n- [x] {first}",
        1,
    )
    with pytest.raises(_module().PullRequestPolicyError, match="every required item"):
        _validate(reordered)


def test_policy_rejects_unchecked_required_checklist_item() -> None:
    body = _body().replace("- [x] I did not turn", "- [ ] I did not turn", 1)
    with pytest.raises(_module().PullRequestPolicyError, match="every required item"):
        _validate(body)


@pytest.mark.parametrize(
    ("body", "message"),
    (
        (_body(head="d" * 40), "does not equal current head"),
        (_body(base="d" * 40), "does not equal current base"),
        (_body().replace("CLEAR —", "PENDING —", 1), "unresolved"),
        (_body().replace("[ACCEPTED] Bounded", "[BLOCKED] Bounded"), "human review gate"),
        (_body().replace("DISCLOSED —", "RECORDED —"), "NONE or DISCLOSED"),
        (_body().replace("ASSIGNED —", "OWNER —"), "ASSIGNED owner"),
    ),
)
def test_policy_fails_closed_on_stale_or_incomplete_record(
    body: str, message: str
) -> None:
    with pytest.raises(_module().PullRequestPolicyError, match=message):
        _validate(body)


def test_post_acceptance_record_mutation_invalidates_marker_and_digest() -> None:
    accepted = _body()
    acceptance = _comment(accepted)
    mutated = accepted.replace("All findings resolved", "Seven findings resolved")
    with pytest.raises(_module().PullRequestPolicyError, match="SHA-256"):
        _validate(mutated, comments=[acceptance])


def test_base_advance_stales_promotion_even_when_body_is_unchanged() -> None:
    body = _body()
    module = _module()
    with pytest.raises(module.PullRequestPolicyError, match="current base"):
        module.validate(
            _event(body, base="d" * 40),
            reviews=[],
            comments=[_comment(body)],
            ci_coordinate=_coordinate(),
            repository_run=_run(),
            test_evidence_manifest=_manifest(),
        )


def test_repository_run_and_integration_coordinate_must_match() -> None:
    body = _body()
    coordinate = _coordinate()
    coordinate["executed_commit"] = "d" * 40
    with pytest.raises(_module().PullRequestPolicyError, match="executed_commit"):
        _module().validate(
            _event(body),
            reviews=[],
            comments=[_comment(body)],
            ci_coordinate=coordinate,
            repository_run=_run(),
            test_evidence_manifest=_manifest(),
        )


def test_mid_run_body_mutation_is_rejected_before_success() -> None:
    body = _body()
    receipt = _validate(body)
    current = _event(body.replace("## Checklist", "A late edit.\n\n## Checklist"))
    with pytest.raises(_module().PullRequestPolicyError, match="changed during"):
        _module().confirm_current_snapshot(receipt, current)


def test_mid_run_review_withdrawal_is_rejected_by_complete_reconfirmation() -> None:
    body = _body()
    receipt = _validate(body)
    digest = _module().promotion_record_sha256(body)
    withdrawn = [{
        "id": 2,
        "user": {"login": "maintainer"},
        "html_url": ACCEPTANCE_URL,
        "author_association": "OWNER",
        "state": "CHANGES_REQUESTED",
        "commit_id": HEAD,
        "body": f"VSTD-HUMAN-ACCEPTANCE: {HEAD} {digest}",
    }]
    with pytest.raises(_module().PullRequestPolicyError, match="current state requests changes"):
        _module().confirm_current_evidence(
            receipt, _event(body), reviews=withdrawn, comments=[_comment(body)],
            ci_coordinate=_coordinate(), repository_run=_run(),
            test_evidence_manifest=_manifest(),
        )


def test_trusted_review_requires_marker_for_exact_record() -> None:
    body = _body()
    digest = _module().promotion_record_sha256(body)
    review = {
        "id": 1,
        "user": {"login": "reviewer"},
        "html_url": ACCEPTANCE_URL,
        "author_association": "COLLABORATOR",
        "state": "APPROVED",
        "commit_id": HEAD,
        "body": f"VSTD-HUMAN-ACCEPTANCE: {HEAD} {digest}",
    }
    result = _module().validate(
        _event(body),
        reviews=[review],
        comments=[],
        ci_coordinate=_coordinate(),
        repository_run=_run(),
        test_evidence_manifest=_manifest(),
    )
    assert result["acceptance_url"] == ACCEPTANCE_URL


@pytest.mark.parametrize(
    ("later_state", "message"),
    (("CHANGES_REQUESTED", "current state requests changes"), ("DISMISSED", "acceptance evidence")),
)
def test_same_reviewer_later_state_revokes_approval(later_state: str, message: str) -> None:
    body = _body()
    digest = _module().promotion_record_sha256(body)
    common = {"user": {"login": "reviewer"}, "author_association": "COLLABORATOR", "commit_id": HEAD}
    reviews = [
        {**common, "id": 1, "html_url": ACCEPTANCE_URL, "state": "APPROVED", "body": f"VSTD-HUMAN-ACCEPTANCE: {HEAD} {digest}"},
        {**common, "id": 2, "html_url": ACCEPTANCE_URL + "-withdrawn", "state": later_state, "body": "withdrawn"},
    ]
    with pytest.raises(_module().PullRequestPolicyError, match=message):
        _validate(body, comments=[], reviews=reviews)


def test_false_none_is_rejected_when_manifest_records_skip() -> None:
    manifest = _manifest(skipped=1)
    with pytest.raises(_module().PullRequestPolicyError, match="NONE.*contradicts"):
        _validate(_body(manifest=manifest, disposition="NONE"), manifest=manifest)


def test_none_is_accepted_only_for_complete_zero_skip_observation() -> None:
    manifest = _manifest(skipped=0)
    result = _validate(_body(manifest=manifest, disposition="NONE"), manifest=manifest)
    assert result["test_evidence_total_skipped"] == 0
    assert result["test_evidence_skip_observation_omission_count"] == 0


def test_false_disclosed_is_rejected_for_complete_zero_skip_observation() -> None:
    manifest = _manifest(skipped=0)
    with pytest.raises(_module().PullRequestPolicyError, match="DISCLOSED.*empty manifest"):
        _validate(_body(manifest=manifest, disposition="DISCLOSED"), manifest=manifest)


def test_false_disclosed_skip_count_is_rejected_against_bound_manifest() -> None:
    manifest = _manifest(skipped=1)
    body = _body(manifest=manifest).replace("total-skipped=1", "total-skipped=0")
    with pytest.raises(_module().PullRequestPolicyError, match="summary contradicts"):
        _validate(body, manifest=manifest)


def test_false_disclosed_observation_omissions_are_rejected() -> None:
    manifest = _manifest(skipped=0)
    manifest["skip_observation_omissions"] = ["coverage"]
    manifest["total_skipped"] = 1
    manifest["reports"][0]["skipped"] = 1
    manifest["reports"][0]["skips"] = [
        {"test": "tests.test_example::test_skip", "reason": "bounded"}
    ]
    with pytest.raises(_module().PullRequestPolicyError, match="omissions are not exact"):
        _validate(_body(manifest=manifest), manifest=manifest)


def test_generic_disclosed_prose_cannot_evade_structured_summary() -> None:
    body = _body().replace(
        "total-skipped=1; skip-observation-omissions=NONE",
        "see the machine manifest",
    )
    with pytest.raises(_module().PullRequestPolicyError, match="NONE or DISCLOSED"):
        _validate(body)


@pytest.mark.parametrize(
    "duplicate",
    (
        f"- Final head commit: `{HEAD}`\n",
        "- Tests skipped or not run: NONE — test-evidence-sha256="
        f"{'f' * 64} — total-skipped=0; skip-observation-omissions=NONE\n",
    ),
)
def test_duplicate_authoritative_promotion_field_is_rejected(duplicate: str) -> None:
    body = _body().replace("## Human review gates", duplicate + "\n## Human review gates")
    with pytest.raises(_module().PullRequestPolicyError, match="must occur exactly once"):
        _validate(body)


@pytest.mark.parametrize("heading", ("Promotion record", "Human review gates"))
def test_duplicate_authoritative_section_is_rejected(heading: str) -> None:
    body = _body() + f"\n## {heading}\n\n- [ACCEPTED] Duplicate — rejected.\n"
    with pytest.raises(_module().PullRequestPolicyError, match="section must occur exactly once"):
        _validate(body)


def test_mismatched_test_evidence_digest_is_rejected() -> None:
    body = _body()
    actual = _module()._canonical_json_sha256(_manifest())
    body = body.replace(f"test-evidence-sha256={actual}", f"test-evidence-sha256={'f' * 64}")
    old_record = next(line.split("`")[1] for line in body.splitlines() if "Promotion record SHA-256" in line)
    body = body.replace(old_record, _module().promotion_record_sha256(body), 1)
    with pytest.raises(_module().PullRequestPolicyError, match="manifest SHA-256"):
        _validate(body)


def _write_report(
    path: Path, *, skipped: bool = False, skip_reason: str = "bounded"
) -> None:
    skip = f'<skipped message="{skip_reason}" />' if skipped else ""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'<testsuite><testcase classname="tests.example" name="test_one">{skip}</testcase></testsuite>', encoding="utf-8")


def _write_expected_reports(root: Path) -> None:
    for kind, coordinate, filename in _module().EXPECTED_REPORTS:
        prefix = _module().REPORT_ARTIFACT_PREFIXES[kind]
        _write_report(root / f"{prefix}-{RUN_ID}-2-{coordinate}" / filename)


def test_manifest_builder_rejects_missing_expected_artifact(tmp_path: Path) -> None:
    with pytest.raises(_module().PullRequestPolicyError, match="missing expected"):
        _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")


@pytest.mark.parametrize("missing_index", range(len(_module().EXPECTED_REPORTS)))
def test_manifest_builder_rejects_each_missing_report(
    tmp_path: Path, missing_index: int
) -> None:
    _write_expected_reports(tmp_path)
    kind, coordinate, filename = _module().EXPECTED_REPORTS[missing_index]
    prefix = _module().REPORT_ARTIFACT_PREFIXES[kind]
    (tmp_path / f"{prefix}-{RUN_ID}-2-{coordinate}" / filename).unlink()
    with pytest.raises(_module().PullRequestPolicyError, match="missing expected"):
        _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")


def test_manifest_validator_rejects_new_unregistered_report() -> None:
    manifest = _manifest()
    manifest["reports"].append(
        {
            "coordinate": "python-3.12",
            "errors": 0,
            "failures": 0,
            "kind": "new-pytest-job",
            "report_sha256": "f" * 64,
            "skipped": 0,
            "skips": [],
            "tests": 1,
        }
    )
    manifest["total_tests"] += 1
    with pytest.raises(_module().PullRequestPolicyError, match="inventory is incomplete"):
        _module()._validate_test_evidence_manifest(
            manifest, run_id=RUN_ID, run_attempt="2"
        )


def test_manifest_builder_rejects_unregistered_artifact(tmp_path: Path) -> None:
    _write_expected_reports(tmp_path)
    _write_report(tmp_path / "new-pytest-job-123-2-python-3.12" / "new.xml")
    with pytest.raises(_module().PullRequestPolicyError, match="unexpected test-evidence artifact"):
        _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")


@pytest.mark.parametrize("reason", ("", " " * 3))
def test_manifest_builder_rejects_skip_without_reason(
    tmp_path: Path, reason: str
) -> None:
    _write_expected_reports(tmp_path)
    kind, coordinate, filename = _module().EXPECTED_REPORTS[0]
    prefix = _module().REPORT_ARTIFACT_PREFIXES[kind]
    _write_report(
        tmp_path / f"{prefix}-{RUN_ID}-2-{coordinate}" / filename,
        skipped=True,
        skip_reason=reason,
    )
    with pytest.raises(_module().PullRequestPolicyError, match="no reason"):
        _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")

    manifest = _manifest()
    manifest["reports"][0]["skips"][0]["reason"] = reason
    with pytest.raises(_module().PullRequestPolicyError, match="skip record is invalid"):
        _module()._validate_test_evidence_manifest(
            manifest, run_id=RUN_ID, run_attempt="2"
        )


def test_manifest_builder_and_validator_reject_oversized_skip_reason(
    tmp_path: Path,
) -> None:
    _write_expected_reports(tmp_path)
    kind, coordinate, filename = _module().EXPECTED_REPORTS[0]
    prefix = _module().REPORT_ARTIFACT_PREFIXES[kind]
    _write_report(
        tmp_path / f"{prefix}-{RUN_ID}-2-{coordinate}" / filename,
        skipped=True,
        skip_reason="x" * (_module().MAX_SKIP_REASON_CHARACTERS + 1),
    )
    with pytest.raises(_module().PullRequestPolicyError, match="reason exceeds"):
        _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")

    manifest = _manifest()
    manifest["reports"][0]["skips"][0]["reason"] = "x" * (
        _module().MAX_SKIP_REASON_CHARACTERS + 1
    )
    with pytest.raises(_module().PullRequestPolicyError, match="skip record is invalid"):
        _module()._validate_test_evidence_manifest(
            manifest, run_id=RUN_ID, run_attempt="2"
        )


def test_expected_reports_match_repository_check_matrix_exactly() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    expected = [
        ("base", f"python-{version}", "base-contracts.xml")
        for version in workflow["jobs"]["base"]["strategy"]["matrix"]["python-version"]
    ]
    expected.extend(
        ("platform", item["coordinate"], "platform-contracts.xml")
        for item in workflow["jobs"]["platform-python-contracts"]["strategy"]["matrix"]["include"]
    )
    expected.extend(
        [
            ("coverage", "python-3.12", "coverage-tests.xml"),
            ("scitt-crypto", "python-3.12", "scitt-crypto.xml"),
            ("artifact-seal", "python-3.12", "artifact-seal.xml"),
        ]
    )
    assert _module().EXPECTED_REPORTS == tuple(expected)


def test_manifest_builder_produces_valid_canonical_artifact(tmp_path: Path) -> None:
    _write_expected_reports(tmp_path)
    manifest = _module().build_test_evidence_manifest(tmp_path, RUN_ID, "2")
    body = _body(manifest=manifest, disposition="NONE")
    result = _validate(body, manifest=manifest)
    assert result["test_evidence_manifest_sha256"] == _module()._canonical_json_sha256(manifest)
    assert result["test_evidence_total_tests"] == 11
    assert result["test_evidence_total_skipped"] == 0
    assert result["test_evidence_skip_observation_omission_count"] == 0


def test_trusted_workflow_never_checks_out_pull_request_code() -> None:
    workflow = (ROOT / ".github/workflows/pr-policy.yml").read_text(encoding="utf-8")
    assert "pull_request_target:" in workflow
    assert "github.event.repository.default_branch" in workflow
    checkout = workflow.split("actions/checkout", 1)[1].split("- name:", 1)[0]
    assert "github.event.pull_request.head.sha }}" not in checkout
    assert "pull_request.head.ref" not in workflow


def test_json_loader_rejects_oversized_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "MAX_JSON_BYTES", 4)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b"12345")
    with pytest.raises(module.PullRequestPolicyError, match="JSON byte limit"):
        module._load_json(evidence)


def test_review_records_fail_closed_at_the_conservative_page_cap() -> None:
    module = _module()
    with pytest.raises(module.PullRequestPolicyError, match="record limit"):
        module._records([{}] * 100)


def test_pull_request_body_has_an_independent_byte_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "MAX_BODY_BYTES", 16)
    with pytest.raises(module.PullRequestPolicyError, match="body exceeds"):
        module.validate(
            _event(_body()),
            reviews=[],
            comments=[],
            ci_coordinate=_coordinate(),
            repository_run=_run(),
            test_evidence_manifest=_manifest(),
        )
