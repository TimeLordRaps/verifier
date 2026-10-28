"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG);
Java unit test report format (JUnit); operating system (OS); pull request (PR);
Verifier Standard (VSTD).

Verify that local preflight checks catch defects before remote push."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import preflight


def _ci_job(name: str) -> dict:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    return workflow["jobs"][name]


def _job_commands(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job["steps"])


@pytest.mark.parametrize(
    ("job_name", "report_stem"),
    (("base", "base-contracts"), ("optional-discovery", "optional-discovery")),
)
def test_protected_ci_audits_the_same_pytest_output_it_publishes(
    job_name: str,
    report_stem: str,
) -> None:
    """Hosted suppression prevention consumes the actual protected test run.

    Summarizing JUnit skip elements is not sufficient: pytest serializes expected
    failures as skipped elements too.  The preflight audit must therefore inspect
    the verbose ``-r`` terminal evidence that distinguishes skip, xfail and xpass.
    """
    job = _ci_job(job_name)
    commands = _job_commands(job)

    assert job_name in _ci_job("conformance-gate")["needs"]
    assert f"--junitxml={report_stem}.xml" in commands
    assert "-rsxX" in commands
    assert f"{report_stem}.pytest.txt" in commands
    assert "from scripts.preflight import check_test_skips" in commands
    assert f"check_test_skips(Path('{report_stem}.pytest.txt').read_text" in commands


def test_optional_discovery_runs_every_declared_parser_fixture_suite() -> None:
    job = _ci_job("optional-discovery")
    commands = _job_commands(job)

    for extra in (
        "discovery-javascript",
        "discovery-rust",
        "discovery-shell",
        "discovery-workflows",
    ):
        assert extra in commands
    for test_file in (
        "tests/test_namespace_javascript.py",
        "tests/test_namespace_systems.py",
        "tests/test_namespace_documents.py",
        "tests/test_namespace_html.py",
        "tests/test_polish0_interface_adversary.py",
    ):
        assert test_file in commands


def test_stdlib_smoke_conforms() -> None:
    assert preflight.check_stdlib_smoke() is True


def test_readme_version_conforms() -> None:
    assert preflight.check_readme_version() is True


def test_readme_version_detects_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "2.0.0"\n', encoding="utf-8")
    (tmp_path / "README.md").write_text('python -m pip install "verifier-standard==1.0.0"\n', encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.check_readme_version() is False


def test_docs_versions_conforms() -> None:
    assert preflight.check_docs_versions() is True


def test_docs_versions_detects_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "2.0.0"\n', encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "TEST.md").write_text('python -m pip install "verifier-standard==1.0.0"\n', encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.check_docs_versions() is False


@pytest.mark.timeout(180)
def test_presentation_gate_conforms() -> None:
    assert preflight.check_presentation_gate() is True


def test_schema_inventory_conforms() -> None:
    assert preflight.check_schema_inventory() is True


@pytest.mark.parametrize("check", [preflight.check_schema_inventory, preflight.check_full_test_suite, preflight.check_test_skips])
def test_nested_test_commands_are_verbose_and_bounded(check, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = []
    def observe(command, **kwargs):
        commands.append(command)
        return 0, "1 passed", ""
    monkeypatch.setattr(preflight, "_run_command", observe)
    assert check()
    tests = [command for command in commands if "pytest" in command]
    assert len(tests) == 1
    assert {"-u", "-vv", "-s", "--durations=10", "--timeout=60"} <= set(tests[0])
    assert not {"-q", "-qq"} & set(tests[0])


def _suite_with_boundary(monkeypatch: pytest.MonkeyPatch, boundary_code: int) -> list[list[str]]:
    commands: list[list[str]] = []

    def observe(command, **kwargs):
        commands.append(command)
        if "pytest" in command:
            return 0, "1 passed", ""
        return boundary_code, "", "[BOUNDARY FAIL] email address in base-contracts.xml"

    monkeypatch.setattr(preflight, "_run_command", observe)
    return commands


def test_the_suite_report_is_scanned_as_the_hosted_run_scans_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The hosted base job fails when its JUnit report fails the release boundary.

    A parametrized id is written into the report as its parameters' text, so a test
    file the source scan passes can still produce a report the release boundary
    rejects; that is how a head passed preflight and failed ten hosted jobs.
    """
    commands = _suite_with_boundary(monkeypatch, 0)
    assert preflight.check_full_test_suite()
    suite, boundary = commands
    assert "scripts.pytest_public_evidence" in suite
    (report,) = [argument.split("=", 1)[1] for argument in suite
                 if argument.startswith("--junitxml=")]
    assert boundary[1:] == [str(preflight.ROOT / "scripts" / "check_release_boundary.py"), report]


def test_a_report_the_release_boundary_rejects_fails_preflight(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _suite_with_boundary(monkeypatch, 1)
    assert not preflight.check_full_test_suite()
    assert "[TEST EVIDENCE] FAIL" in capsys.readouterr().out


def test_git_signatures_on_head_or_range() -> None:
    assert isinstance(preflight.check_git_signatures("HEAD~1..HEAD"), bool)


@pytest.mark.timeout(180)
def test_preflight_main_execution() -> None:
    # An unavailable attached description is UNKNOWN, distinct from a failed check.
    assert preflight.main() in (0, 1, 2)


def test_classify_skip_reason_rubric_tags() -> None:
    for category in preflight.TEST_SKIP_RUBRIC_CATEGORIES:
        assert preflight.classify_skip_reason(f"[{category}] Explicit justification") == category
        assert preflight.classify_skip_reason(f"{category}: Explicit justification") == category


def test_classify_skip_reason_heuristics() -> None:
    assert (
        preflight.classify_skip_reason("symlink creation is unavailable (errno=22, winerror=1314)")
        == "OS_CAPABILITY_GUARD"
    )
    assert (
        preflight.classify_skip_reason("first-in, first-out special objects are unavailable")
        == "OS_CAPABILITY_GUARD"
    )
    assert (
        preflight.classify_skip_reason("optional scitt dependency not installed")
        == "OPTIONAL_DEPENDENCY_ABSENT"
    )
    assert (
        preflight.classify_skip_reason("arbitrary unknown reason without justification")
        == "UNCLASSIFIED"
    )


def test_audit_test_skips_classified() -> None:
    sample_output = (
        "SKIPPED [33] tests/test_artifact_control.py:109: symlink creation is unavailable (errno=22, winerror=1314)\n"
        "SKIPPED [5] tests/test_artifact_control.py:117: first-in, first-out special objects are unavailable\n"
        "SKIPPED [1] tests/test_graph_topology_integration.py:160: named pipe creation requires Unix\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is True
    assert counts["OS_CAPABILITY_GUARD"] == 39
    assert len(unclassified) == 0
    assert preflight.check_test_skips(sample_output) is True


def test_audit_test_skips_detects_unclassified() -> None:
    sample_output = (
        "SKIPPED [1] tests/test_foo.py:12: arbitrary unclassified skip\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is False
    assert len(unclassified) == 1
    assert unclassified[0] == ("tests/test_foo.py:12", "arbitrary unclassified skip")
    assert preflight.check_test_skips(sample_output) is False


def test_audit_test_skips_handles_windows_drive_letters_and_node_ids() -> None:
    drive_e = "E" + ":\\"
    drive_c = "C" + ":\\"
    sample_output = (
        f"SKIPPED [33] {drive_e}verifier\\tests\\test_artifact_control.py:109: symlink creation is unavailable (errno=22, winerror=1314)\n"
        "SKIPPED [1] tests/test_foo.py::test_bar: [`OPTIONAL_DEPENDENCY_ABSENT`] missing extra\n"
        f"SKIPPED {drive_c}repo\\tests\\test_baz.py:42: EXTERNAL_SERVICE_BOUNDARY - live endpoint offline\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is True
    assert counts["OS_CAPABILITY_GUARD"] == 33
    assert counts["OPTIONAL_DEPENDENCY_ABSENT"] == 1
    assert counts["EXTERNAL_SERVICE_BOUNDARY"] == 1
    assert len(unclassified) == 0


def test_audit_test_skips_detects_summary_count_discrepancy() -> None:
    sample_output = (
        "SKIPPED [5] tests/test_artifact_control.py:117: first-in, first-out special objects are unavailable\n"
        "=========================== 100 passed, 39 skipped in 10.50s ===========================\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is False
    assert counts["OS_CAPABILITY_GUARD"] == 5
    assert any("PYTEST_SUMMARY_DISCREPANCY" in item[0] for item in unclassified)
    assert any("pytest reported 39 skipped tests, but audit parsed only 5" in item[1] for item in unclassified)


def test_audit_test_skips_rejects_summary_that_undercounts_details() -> None:
    sample_output = (
        "SKIPPED [2] tests/test_links.py:12: OS_CAPABILITY_GUARD: symlink unavailable\n"
        "=========================== 8 passed, 1 skipped in 0.10s ===========================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert counts["OS_CAPABILITY_GUARD"] == 2
    assert any(item[0] == "PYTEST_SUMMARY_DISCREPANCY" for item in unclassified)


def test_audit_test_skips_rejects_xfailed_test_as_unclosed_suppression(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sample_output = (
        "XFAIL tests/test_policy.py::test_required_behavior - known defect\n"
        "==================== 8 passed, 1 xfailed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert sum(counts.values()) == 0
    assert any(item[0] == "PYTEST_XFAIL_PRESENT" for item in unclassified)
    assert preflight.check_test_skips(sample_output) is False
    rendered = capsys.readouterr().out
    assert "complete clean run" not in rendered
    assert "XFAIL and XPASS have no passing-coverage rubric" in rendered


def test_audit_test_skips_rejects_non_strict_xpass() -> None:
    sample_output = (
        "XPASS tests/test_policy.py::test_required_behavior - defect unexpectedly passed\n"
        "==================== 8 passed, 1 xpassed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert sum(counts.values()) == 0
    assert any(item[0] == "PYTEST_XPASS_PRESENT" for item in unclassified)


def test_audit_test_skips_rejects_strict_xpass_failure() -> None:
    sample_output = (
        "FAILED tests/test_policy.py::test_required_behavior\n"
        "[XPASS(strict)] known defect\n"
        "==================== 1 failed, 8 passed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert sum(counts.values()) == 0
    assert any(item[0] == "PYTEST_STRICT_XPASS_PRESENT" for item in unclassified)


def test_audit_test_skips_preserves_skip_counts_while_rejecting_xfail() -> None:
    sample_output = (
        "SKIPPED [2] tests/test_links.py:12: OS_CAPABILITY_GUARD: symlink unavailable\n"
        "XFAIL tests/test_policy.py::test_required_behavior - known defect\n"
        "==================== 8 passed, 2 skipped, 1 xfailed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert counts["OS_CAPABILITY_GUARD"] == 2
    assert any(item[0] == "PYTEST_XFAIL_PRESENT" for item in unclassified)


def test_xfail_finding_cannot_mask_a_missing_skip_detail() -> None:
    sample_output = (
        "SKIPPED [1] tests/test_links.py:12: OS_CAPABILITY_GUARD: symlink unavailable\n"
        "XFAIL tests/test_policy.py::test_required_behavior - known defect\n"
        "==================== 8 passed, 2 skipped, 1 xfailed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert counts["OS_CAPABILITY_GUARD"] == 1
    assert any(item[0] == "PYTEST_XFAIL_PRESENT" for item in unclassified)
    assert any(item[0] == "PYTEST_SUMMARY_DISCREPANCY" for item in unclassified)


@pytest.mark.parametrize(
    "sample_output,code",
    (
        (
            "==================== 8 passed, 1 xfailed in 0.10s ====================\n",
            "PYTEST_XFAIL_SUMMARY_DISCREPANCY",
        ),
        (
            "==================== 8 passed, 1 xpassed in 0.10s ====================\n",
            "PYTEST_XPASS_SUMMARY_DISCREPANCY",
        ),
        (
            "XFAIL tests/test_policy.py::test_required_behavior - known defect\n",
            "PYTEST_XFAIL_PRESENT",
        ),
    ),
)
def test_audit_test_skips_rejects_truncated_suppression_reporting(
    sample_output: str,
    code: str,
) -> None:
    success, _, unclassified = preflight.audit_test_skips(sample_output)

    assert success is False
    assert any(item[0] == code for item in unclassified)


def test_audit_test_skips_accepts_a_clean_pytest_run() -> None:
    sample_output = (
        "tests/test_policy.py::test_required_behavior PASSED\n"
        "==================== 9 passed in 0.10s ====================\n"
    )

    success, counts, unclassified = preflight.audit_test_skips(sample_output)

    assert success is True
    assert sum(counts.values()) == 0
    assert unclassified == []
    assert preflight.check_test_skips(sample_output) is True



# --- The pull-request description gate before a push -------------------------------

OWNER_REPOSITORY = "Owner/verifier"
PUSH_URL = "https://github.com/Owner/verifier.git"
PUSHED = "1" * 40
BEFORE = "2" * 40


def _pull(number: int, owner: str = "Owner", name: str = "verifier") -> dict:
    return {"number": number, "headRepository": {"name": name},
            "headRepositoryOwner": {"login": owner}}


def _fake_github(monkeypatch: pytest.MonkeyPatch, pulls_by_branch: dict[str, list[dict]], *,
                 described: tuple[str, str] | None = None, gh_status: int = 0,
                 unrevised: frozenset[str] = frozenset()) -> list[list[str]]:
    """Stand in for gh and for both description checks.

    The description check passes only for `described` (number, commit) and fails for
    any other pull request and commit. Asked with no arguments, as the gate asked before
    2026-09-23, it answers the way the real script did for a local branch without a pull
    request: a pass. The revision check fails for the pull requests in `unrevised`.
    """
    calls: list[list[str]] = []

    def run(cmd: list[str], **kwargs) -> tuple[int, str, str]:
        calls.append(cmd)
        if cmd[:2] == ["git", "rev-parse"]:
            return 0, "", ""  # the signature range; signatures are not under test here
        if cmd[:3] == ["gh", "pr", "list"]:
            if gh_status:
                return gh_status, "", "gh: Bad credentials (401)"
            return 0, json.dumps(pulls_by_branch.get(cmd[cmd.index("--head") + 1], [])), ""
        if str(cmd[1]).endswith("check_pr_description_revision.py"):
            number = cmd[cmd.index("--pr") + 1]
            return (1 if number in unrevised else 0), "[PR DESCRIPTION CHANGE] stub", ""
        if str(cmd[1]).endswith("check_pr_description.py"):
            if len(cmd) == 2:
                return 0, "[PR DESCRIPTION] PASS: no pull request is attached to this branch.", ""
            commit = cmd[cmd.index("--commit") + 1] if "--commit" in cmd else None
            asked = (cmd[cmd.index("--pr") + 1], commit)
            return (0 if described == asked else 1), "[PR DESCRIPTION] stub", ""
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(preflight, "_run_command", run)
    return calls


def _gh_branches(calls: list[list[str]]) -> list[str]:
    return [cmd[cmd.index("--head") + 1] for cmd in calls if cmd[:3] == ["gh", "pr", "list"]]


def test_a_push_under_another_name_is_checked_against_the_pull_request_it_moves(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduces the vacuous pass this gate had until 2026-09-23.

    `git push origin work:feature` moves the pull request on `feature`. The gate asked
    about the local branch `work`, found no pull request, and passed. Here the pull
    request's description does not describe the pushed commit, so the push must fail.
    """
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"refs/heads/work {PUSHED} refs/heads/feature {BEFORE}\n"))
    for check in ("check_git_signatures", "check_readme_version", "check_docs_versions",
                  "check_stdlib_smoke", "check_presentation_gate", "check_schema_inventory"):
        monkeypatch.setattr(preflight, check, lambda *args: True)
    calls = _fake_github(monkeypatch, {"feature": [_pull(7)]}, described=("7", BEFORE))

    assert preflight.handle_pre_push(["origin", PUSH_URL]) == 1
    assert _gh_branches(calls) == ["feature"]
    checked = [cmd for cmd in calls if str(cmd[1]).endswith("check_pr_description.py")]
    assert len(checked) == 1
    assert {"--pr", "7", "--repo", OWNER_REPOSITORY, "--commit", PUSHED,
            "--require-pull-request", "--pre-push-pending-run"} <= set(checked[0])


def test_a_description_that_binds_the_pushed_commit_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, {"feature": [_pull(7)]}, described=("7", PUSHED))
    assert preflight.check_pr_descriptions_for_push(
        [("refs/heads/work", PUSHED, "refs/heads/feature", BEFORE)], ["origin", PUSH_URL])


def test_a_push_whose_description_was_not_revised_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every push must come with a revised description, even one that still reads true.

    Here the description already describes the pushed commit, so only the revision
    rule can refuse the push. The accuracy check still runs, so both verdicts are
    reported rather than the first masking the second.
    """
    calls = _fake_github(monkeypatch, {"feature": [_pull(7)]}, described=("7", PUSHED),
                         unrevised=frozenset({"7"}))
    assert not preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], ["origin", PUSH_URL])
    (revision,) = [cmd for cmd in calls if str(cmd[1]).endswith("check_pr_description_revision.py")]
    assert {"--pr", "7", "--repo", OWNER_REPOSITORY} <= set(revision)
    assert "--head" not in revision and "--body" not in revision  # the live description, current head
    assert any(str(cmd[1]).endswith("check_pr_description.py") for cmd in calls)


@pytest.mark.parametrize("failure", ["status", "missing"])
def test_an_unanswered_lookup_fails_the_push(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A question gh could not answer is not a no."""
    if failure == "status":
        _fake_github(monkeypatch, {}, gh_status=1)
    else:
        def run(cmd: list[str], **kwargs):
            raise FileNotFoundError("gh")
        monkeypatch.setattr(preflight, "_run_command", run)
    assert not preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], ["origin", PUSH_URL])


def test_failed_github_lookup_does_not_print_credentials(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    secret = "ghp_" + "A" * 24

    def run(command: list[str], **kwargs: object) -> tuple[int, str, str]:
        assert command[:3] == ["gh", "pr", "list"]
        return 1, "", "request failed with " + secret

    monkeypatch.setattr(preflight, "_run_command", run)
    assert not preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], ["origin", PUSH_URL])
    output = capsys.readouterr().out
    assert secret not in output
    assert "FAIL" in output


def test_branch_name_is_not_echoed_to_hook_logs(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    secret = "ghp_" + "B" * 24
    branch = "feature-" + secret
    _fake_github(monkeypatch, {branch: []})
    assert preflight.check_pr_descriptions_for_push(
        [("refs/heads/work", PUSHED, "refs/heads/" + branch, BEFORE)], ["origin", PUSH_URL])
    assert secret not in capsys.readouterr().out


def test_a_fork_pull_request_on_the_same_branch_name_is_not_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_github(monkeypatch, {"feature": [_pull(9, owner="Someone")]})
    assert preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], ["origin", PUSH_URL])
    assert not any(str(cmd[1]).endswith("check_pr_description.py") for cmd in calls)


def test_deletions_and_tags_move_no_branch_head(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_github(monkeypatch, {})
    pushes = [("(delete)", preflight.ZERO_OID, "refs/heads/feature", BEFORE),
              ("refs/tags/v1", PUSHED, "refs/tags/v1", preflight.ZERO_OID)]
    assert preflight.check_pr_descriptions_for_push(pushes, ["origin", PUSH_URL])
    assert calls == []


def test_a_remote_off_github_passes_without_printing_its_url(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    calls = _fake_github(monkeypatch, {})
    secret = "tok" + "en-value"
    # Assembled at run time: the boundary scanner rejects a credential-bearing remote
    # address written out in any tracked file, this one included.
    url = "@".join(["https://user:" + secret, "git.example.invalid/owner/verifier.git"])
    assert preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], ["mirror", url])
    assert calls == []
    assert secret not in capsys.readouterr().out


def test_a_push_to_an_unknown_repository_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_github(monkeypatch, {})
    assert not preflight.check_pr_descriptions_for_push(
        [("refs/heads/feature", PUSHED, "refs/heads/feature", BEFORE)], [])


# Joined at run time: the presentation gate reads a user name joined to a host by an
# at sign as a leaked email address, in any tracked file, this one included.
AT = "@"


# Named, never left to the default: a default id is the parameter's own text, and ids
# are written into the test evidence, which the release boundary scans like any other
# published text. Three of these addresses would reach it joined.
@pytest.mark.parametrize(("url", "expected"), [
    ("https://github.com/Owner/verifier.git", OWNER_REPOSITORY),
    ("https://github.com/Owner/verifier", OWNER_REPOSITORY),
    ("https://github.com/Owner/verifier/", OWNER_REPOSITORY),
    ("https://user" + AT + "github.com/Owner/verifier.git", OWNER_REPOSITORY),
    ("git" + AT + "github.com:Owner/verifier.git", OWNER_REPOSITORY),
    ("ssh://git" + AT + "github.com/Owner/verifier.git", OWNER_REPOSITORY),
    ("https://github.com.example.invalid/Owner/verifier.git", None),
    ("https://example.invalid/github.com/Owner/verifier.git", None),
    ("https://github.com/Owner", None),
    ("../mirrors/verifier.git", None),
], ids=[
    "https-git",
    "https-bare",
    "https-slash",
    "https-auth",
    "git-scp",
    "ssh-git",
    "invalid-host-domain",
    "invalid-host-subdomain",
    "owner-without-repo",
    "relative-mirror",
])
def test_github_remote_urls_name_their_repository(url: str, expected: str | None) -> None:
    assert preflight.github_repository(url) == expected
