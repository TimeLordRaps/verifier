"""Terminology: JavaScript Object Notation (JSON); pull request (PR).

Qualify the check that refuses a push whose description was not revised.

The rule: a push is refused when the pull request's description is word for word the
one in force when its current head was pushed. Most tests here are pushes the check
must refuse; the passes that remain discriminate between the moments and revisions
it could mistake for the reference.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Owner/verifier"
HEAD = "a" * 40
PUSHED_AT = "2026-09-23T10:00:00Z"


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_pr_description_changed", ROOT / "scripts" / "check_pr_description_changed.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


CHANGED = _load()


def _run(created_at: str, event: str = "pull_request", pulls: tuple[int, ...] = (7,)) -> dict:
    return {"created_at": created_at, "event": event, "pull_requests": list(pulls)}


def _revision(edited_at: str, text: str | None, deleted: bool = False) -> dict:
    return {"editedAt": edited_at, "deletedAt": edited_at if deleted else None, "diff": text}


def _fake_github(monkeypatch: pytest.MonkeyPatch, *, live: str, runs: list[dict],
                 revisions: list[dict], page_size: int = 100) -> list[list[str]]:
    """Stand in for gh: the live pull request, the runs on HEAD, the revision pages."""

    calls: list[list[str]] = []

    def gh(arguments: list[str]) -> str:
        calls.append(arguments)
        if arguments[:2] == ["pr", "view"]:
            return json.dumps({"body": live, "headRefOid": HEAD})
        if arguments[:2] == ["api", "--paginate"]:
            assert f"head_sha={HEAD}" in arguments[2]
            return "".join(json.dumps(run) + "\n" for run in runs)
        if arguments[:2] == ["api", "graphql"]:
            cursor = next((int(a.split("=", 1)[1]) for a in arguments if a.startswith("cursor=")), 0)
            page = revisions[cursor:cursor + page_size]
            more = cursor + page_size < len(revisions)
            return json.dumps({"data": {"repository": {"pullRequest": {"userContentEdits": {
                "pageInfo": {"hasNextPage": more, "endCursor": str(cursor + page_size)},
                "nodes": page,
            }}}}})
        raise AssertionError(f"unexpected gh call {arguments}")

    monkeypatch.setattr(CHANGED, "_gh", gh)
    return calls


def _revised(monkeypatch: pytest.MonkeyPatch, **github) -> bool:
    _fake_github(monkeypatch, **github)
    revised, _message = CHANGED.check(REPOSITORY, 7)
    return revised


def test_a_description_left_as_it_was_at_the_push_is_refused(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _fake_github(monkeypatch, live="Binds head a.", runs=[_run(PUSHED_AT)],
                 revisions=[_revision("2026-09-23T09:59:00Z", "Binds head a."),
                            _revision("2026-09-23T09:00:00Z", "Opened.")])
    assert CHANGED.main(["--repo", REPOSITORY, "--pr", "7"]) == 1
    output = capsys.readouterr().out
    assert "word for word" in output and HEAD[:12] in output


@pytest.mark.parametrize("live", [
    "Binds head a.\n",
    "  Binds   head\na. ",
    "Binds head a.".replace(" ", "\r\n"),
])
def test_spacing_and_line_endings_are_not_a_revision(live: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _revised(monkeypatch, live=live, runs=[_run(PUSHED_AT)],
                        revisions=[_revision("2026-09-23T09:59:00Z", "Binds head a.")])


@pytest.mark.parametrize("live", ["Binds head b.", "head Binds a.", "Binds head a. Adds TOKEN."])
def test_any_change_of_words_is_a_revision(live: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _revised(monkeypatch, live=live, runs=[_run(PUSHED_AT)],
                    revisions=[_revision("2026-09-23T09:59:00Z", "Binds head a.")])


def test_an_edit_undone_before_the_next_push_is_not_a_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _revised(monkeypatch, live="Binds head a.", runs=[_run(PUSHED_AT)], revisions=[
        _revision("2026-09-23T10:30:00Z", "Binds head a."),
        _revision("2026-09-23T10:20:00Z", "Binds head b."),
        _revision("2026-09-23T09:59:00Z", "Binds head a."),
    ])


def test_the_push_is_the_first_run_not_the_runs_its_edits_fired(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every edit fires more runs on the same head. Taking any but the first as the
    push would make the revised description its own reference."""
    assert _revised(monkeypatch, live="Binds head b.",
                    runs=[_run("2026-09-23T10:31:00Z", "pull_request_target"), _run(PUSHED_AT)],
                    revisions=[_revision("2026-09-23T10:30:00Z", "Binds head b."),
                               _revision("2026-09-23T09:59:00Z", "Binds head a.")])


def test_a_revision_made_in_the_second_of_the_push_was_in_force_at_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _revised(monkeypatch, live="Binds head a.", runs=[_run(PUSHED_AT)],
                        revisions=[_revision(PUSHED_AT, "Binds head a."),
                                   _revision("2026-09-23T09:00:00Z", "Opened.")])


def test_runs_from_branch_pushes_and_other_pull_requests_are_not_this_push(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The branch push and the other pull request both saw the head first, while the
    description still read "Opened."; neither is this pull request's push."""
    runs = [_run("2026-09-23T08:00:00Z", "push", ()), _run("2026-09-23T08:30:00Z", pulls=(9,)),
            _run(PUSHED_AT)]
    assert not _revised(monkeypatch, live="Binds head a.", runs=runs, revisions=[
        _revision("2026-09-23T09:59:00Z", "Binds head a."),
        _revision("2026-09-23T07:00:00Z", "Opened."),
    ])


def test_a_description_never_edited_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _revised(monkeypatch, live="Opened.", runs=[_run(PUSHED_AT)], revisions=[])


def test_the_reference_is_found_past_the_first_page(monkeypatch: pytest.MonkeyPatch) -> None:
    revisions = [_revision(f"2026-09-23T11:{minute:02d}:00Z", f"Edit {minute}.")
                 for minute in range(59, 0, -1)] + [_revision("2026-09-23T09:59:00Z", "Binds head a.")]
    assert not _revised(monkeypatch, live="Binds head a.", runs=[_run(PUSHED_AT)],
                        revisions=revisions, page_size=10)


@pytest.mark.parametrize("case", ["no run", "deleted revision", "gh fails", "no revision old enough"])
def test_what_cannot_be_established_refuses_the_push(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A question GitHub did not answer is not a no."""
    runs = [] if case == "no run" else [_run(PUSHED_AT)]
    revisions = {
        "deleted revision": [_revision("2026-09-23T09:59:00Z", None, deleted=True)],
        "no revision old enough": [_revision("2026-09-23T10:05:00Z", "Binds head b.")],
    }.get(case, [_revision("2026-09-23T09:59:00Z", "Binds head a.")])
    _fake_github(monkeypatch, live="Binds head b.", runs=runs, revisions=revisions)
    if case == "gh fails":
        def gh(arguments: list[str]) -> str:
            raise CHANGED.Unanswered("gh api failed: 401 Bad credentials")
        monkeypatch.setattr(CHANGED, "_gh", gh)
    assert CHANGED.main(["--repo", REPOSITORY, "--pr", "7"]) == 1


@pytest.mark.parametrize("failure", ["exit status", "not installed", "timed out"])
def test_a_failed_gh_is_unanswered_not_an_empty_answer(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every other test stands in for gh; this one stands in for the process under it."""

    def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        assert cmd[0] == "gh"
        if failure == "not installed":
            raise FileNotFoundError("gh")
        if failure == "timed out":
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="gh: Bad credentials (401)")

    monkeypatch.setattr(CHANGED.subprocess, "run", run)
    with pytest.raises(CHANGED.Unanswered):
        CHANGED._gh(["pr", "view", "7"])


def test_the_workflow_judges_the_description_its_push_event_carried(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The hosted job passes the previous head and the description as the push carried
    it; the live description, edited since, must not stand in for it."""
    calls = _fake_github(monkeypatch, live="Revised after the push.", runs=[_run(PUSHED_AT)],
                         revisions=[_revision("2026-09-23T10:40:00Z", "Revised after the push."),
                                    _revision("2026-09-23T09:59:00Z", "Binds head a.")])
    carried = tmp_path / "description.md"
    carried.write_text("Binds head a.", encoding="utf-8")
    assert CHANGED.main(["--repo", REPOSITORY, "--pr", "7", "--head", HEAD,
                         "--body", str(carried)]) == 1
    assert not any(call[:2] == ["pr", "view"] for call in calls)
