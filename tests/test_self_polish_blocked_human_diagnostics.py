"""Human diagnostics for a refresh-blocked ``vstd polish`` run.

Refresh is a prerequisite, not polish. When root ``objects.vstd`` freshness blocks
assessment, the human output must name the exact focus of each bounded finding and
must never imply package conformance.
"""

from __future__ import annotations

import json

from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish
from verifier.runtime import self_polish_tiers

REVIEW_OBLIGATION = "VSTD-T0.7-source-and-mechanism-freshness"
REVIEW_REASON = (
    "SOURCE_SEMANTICS_CHANGED requires renewed semantic review of "
    "classification POLICY before root objects.vstd can be refreshed."
)
REVIEW_NEXT_ACTION = (
    "Review the changed source semantics for this exact object and "
    "classification, then rerun the focused source-freshness obligation."
)
REVIEW_RERUN = [
    "vstd", "gate", "--object", "example-object",
    "--obligation", REVIEW_OBLIGATION,
]


def _review_refresh(*_args, **_kwargs):
    return {
        "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
        "status": "UNKNOWN",
        "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
        "review_required": [{
            "path": "src/example.py",
            "reason": "SOURCE_SEMANTICS_CHANGED",
            "object_id": "example-object",
            "classifications": ["POLICY"],
            "obligations": [],
        }],
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }


def _read_only_refresh(*_args, **_kwargs):
    digest = "sha256:" + "1" * 64
    return {
        "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
        "status": "REFRESH_REQUIRED",
        "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
        "before_digest": digest,
        "after_digest": digest,
        "backup_digest": None,
        "source_census_digest": digest,
        "migration_mechanism_digest": digest,
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }


def _unexpected_assessor(*_args, **_kwargs):
    raise AssertionError("stale package assessor must not run")


def _run(monkeypatch, tmp_path, refresh, tier: str, *extra: str) -> int:
    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", refresh,
    )
    monkeypatch.setattr(
        package_polish, "assess_package_polish", _unexpected_assessor,
    )
    return self_polish_tiers.handle_self_polish_tier_argv([
        tier, "--source-root", str(tmp_path), "--manifest-refresh", "check",
        *extra,
    ])


def test_tier_zero_refresh_blocked_human_output_names_exact_focus(
        monkeypatch, tmp_path, capsys) -> None:
    exit_code = _run(monkeypatch, tmp_path, _review_refresh, "0")
    output = capsys.readouterr().out

    assert exit_code == 2
    assert output.splitlines()[0].startswith("[UNKNOWN] root objects.vstd refresh")
    assert "assessment=NOT_RUN" in output
    assert "NOT_ESTABLISHED" in output
    assert "PASS" not in output
    assert (
        "[UNKNOWN] object=example-object obligation=" + REVIEW_OBLIGATION
        + " gate=manifest-refresh coordinate=file:src/example.py"
        + " object_kind=POLICY"
    ) in output
    assert "  reason=" + REVIEW_REASON in output
    assert "  Next: " + REVIEW_NEXT_ACTION in output
    assert "  rerun_argv=" + json.dumps(REVIEW_RERUN, separators=(",", ":")) in output


def _many_files_refresh(file_count: int, kinds: tuple[str, ...]):
    def refresh(*_args, **_kwargs):
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": f"src/module_{index:03d}.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": f"object-{index:03d}",
                "classifications": list(kinds),
                "obligations": [],
            } for index in range(file_count)],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }
    return refresh


def test_many_changed_files_print_one_line_each_and_one_next_step(
        monkeypatch, tmp_path, capsys) -> None:
    """A large review must tell the developer what to do next, not repeat per kind.

    One changed file is reported once per classified kind, so 40 files with three
    kinds each used to print 120 near-identical blocks.  The human view groups them
    by file and names a single next step; ``--json`` keeps every finding.
    """
    kinds = ("POLICY", "ACTUATOR", "ASSET")
    refresh = _many_files_refresh(40, kinds)

    exit_code = _run(monkeypatch, tmp_path, refresh, "0")
    output = capsys.readouterr().out
    lines = output.splitlines()

    assert exit_code == 2
    assert lines[0].startswith("[UNKNOWN] root objects.vstd refresh")
    assert "assessment=NOT_RUN" in output and "PASS" not in output
    assert len(lines) < 60
    assert "40 changed source files" in output and "120 findings" in output
    assert "file:src/module_000.py" in output
    assert "kinds=ACTUATOR,ASSET,POLICY" in output
    assert "more files" in output
    next_lines = [line for line in lines if line.startswith("Next:")]
    assert len(next_lines) == 1
    assert "src/module_000.py" in next_lines[0]
    assert json.dumps(
        ["vstd", "gate", "--object", "object-000", "--obligation", REVIEW_OBLIGATION],
        separators=(",", ":"),
    ) in next_lines[0]

    exit_code = _run(monkeypatch, tmp_path, refresh, "0", "--json")
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert len(report["findings"]) == 120


def test_tier_zero_repository_blocker_names_repository_focus_and_rerun(
        monkeypatch, tmp_path, capsys) -> None:
    exit_code = _run(monkeypatch, tmp_path, _read_only_refresh, "0")
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "assessment=NOT_RUN" in output
    assert "- MANIFEST_REFRESH_REQUIRED_READ_ONLY" in output
    assert "[UNKNOWN] object=<repository> obligation=" in output
    assert "  reason=" in output
    assert "  Next: " in output
    assert '  rerun_argv=["vstd","polish","0","--json"]' in output


def test_tier_three_refresh_blocked_human_and_json_keep_tiers_zero_to_three(
        monkeypatch, tmp_path, capsys) -> None:
    exit_code = _run(monkeypatch, tmp_path, _read_only_refresh, "3")
    human = capsys.readouterr().out

    assert exit_code == 2
    for depth in (1, 2, 3):
        assert f"package tier {depth}: execution=NOT_RUN" in human
    for depth in (0, 1, 2, 3):
        assert f"native tier {depth}" in human
    assert 'blocking_prerequisite={' in human
    assert '"tier":0' in human
    assert "- MANIFEST_REFRESH_REQUIRED_READ_ONLY" in human

    exit_code = _run(monkeypatch, tmp_path, _read_only_refresh, "3", "--json")
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["assessment_execution_status"] == "NOT_RUN"
    assert sorted(report["native_diagnostics"]["tier_execution"]) == [
        "0", "1", "2", "3",
    ]
    for depth in ("0", "1", "2", "3"):
        blocking = report["native_diagnostics"]["tier_execution"][depth][
            "blocking_prerequisite"
        ]
        assert blocking["tier"] == 0
        assert blocking["observed_status"] == "UNKNOWN"


def test_refresh_failure_maps_to_exit_one_with_human_focus(
        monkeypatch, tmp_path, capsys) -> None:
    def failed_refresh(*_args, **_kwargs):
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "FAIL",
            "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }

    exit_code = _run(monkeypatch, tmp_path, failed_refresh, "0")
    output = capsys.readouterr().out

    assert exit_code == 1
    assert output.splitlines()[0].startswith("[FAIL] root objects.vstd refresh")
    assert "assessment=NOT_RUN" in output


def test_tier_zero_refresh_focus_is_escaped_before_terminal_output(
        monkeypatch, tmp_path, capsys) -> None:
    hostile_object = "example\x1b[2J-object"
    hostile_reason = "SOURCE_SEMANTICS_CHANGED\x1b]0;owned\x07 requires review"

    def hostile_refresh(*_args, **_kwargs):
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/example.py",
                "reason": hostile_reason,
                "object_id": hostile_object,
                "classifications": ["POLICY"],
                "obligations": [],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }

    exit_code = _run(monkeypatch, tmp_path, hostile_refresh, "0")
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "object=example\\u001b[2J-object" in output
    assert "reason=SOURCE_SEMANTICS_CHANGED\\u001b]0;owned\\u0007 requires" in output
