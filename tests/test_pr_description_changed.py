"""Terminology: pull request (PR). Push records differ from workflow time."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = "Owner/verifier"
FIRST = "a" * 40
SECOND = "b" * 40


@pytest.fixture
def gate():
    path = ROOT / "scripts/check_pr_description_changed.py"
    assert path.is_file(), "The required push-history checker is absent"
    spec = importlib.util.spec_from_file_location("history_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def event(action="opened", head=FIRST, body="Original description", before=None):
    value = {"action": action, "number": 7, "repository": {"full_name": REPO},
             "pull_request": {"number": 7, "body": body, "head": {"sha": head},
                              "base": {"sha": "fc2a20c68d01920eda7e4e1bf14dfbcb334a7634", "repo": {"full_name": REPO}}}}
    if before is not None: value.update(before=before, after=head)
    return value


def capture(gate, payload, records=None, run=10):
    return gate.evaluate(payload, lambda head: (records or {})[head], repository=REPO, run_id=run, attempt=1)


def test_first_opened_event_establishes_only_explicit_baseline(gate):
    status, record = capture(gate, event())
    assert status == "BASELINE"
    assert record["before"] is None and record["action"] == "opened"
    assert "Original description" not in str(record)
    assert "created_at" not in record


@pytest.mark.parametrize("body,expected", [("Revised description", "PASS"), ("Original description", "FAIL"), (" Original\n description  ", "FAIL")])
def test_new_push_compares_recorded_normalized_words(gate, body, expected):
    _, first = capture(gate, event())
    status, current = capture(gate, event("synchronize", SECOND, body, FIRST), {FIRST: first}, 11)
    assert status == expected
    assert current["head"] == SECOND and current["before"] == FIRST


@pytest.mark.parametrize("action", ["edited", "reopened", "ready_for_review"])
@pytest.mark.parametrize("pushed_body,expected", [("Original description", "FAIL"), ("Revised description", "PASS")])
def test_later_description_edits_cannot_rewrite_the_push(gate, action, pushed_body, expected):
    _, first = capture(gate, event())
    _, second = capture(gate, event("synchronize", SECOND, pushed_body, FIRST), {FIRST: first}, 11)
    status, output = capture(gate, event(action, SECOND, "Entirely different late edit"), {FIRST: first, SECOND: second}, 12)
    assert status == expected
    assert output is None, "Edits must not create replacement push observations"


@pytest.mark.parametrize("payload", [event("edited"), event("synchronize", SECOND, "Changed", FIRST), event("synchronize", SECOND, "Changed"), event("closed")])
def test_missing_history_or_unsupported_event_is_unknown(gate, payload):
    with pytest.raises(gate.Unknown):
        capture(gate, payload)


def provenance(record):
    artifact = {"name": f"pr-description-push-7-{record['head']}", "expired": False,
                "workflow_run": {"id": 10, "head_sha": record["head"]}}
    run = {"id": 10, "run_attempt": 1, "event": "pull_request", "head_sha": record["head"],
           "repository": {"full_name": REPO}, "pull_requests": [{"number": 7, "head": {"sha": record["head"]},
               "base": {"sha": "fc2a20c68d01920eda7e4e1bf14dfbcb334a7634"}}], "workflow_id": 20}
    workflow = {"id": 20, "path": ".github/workflows/pr-description.yml"}
    return artifact, run, workflow


def test_observation_requires_bound_platform_provenance(gate):
    _, record = capture(gate, event())
    assert gate.validate_record(record, *provenance(record), repository=REPO, number=7, head=FIRST, default_head=gate.BOOTSTRAP_BASE) == record


@pytest.mark.parametrize("fault", ["head", "repository", "pr", "event", "workflow", "expired", "run", "attempt", "digest", "action", "before", "extra"])
def test_wrong_or_malformed_history_is_unknown(gate, fault):
    _, record = capture(gate, event())
    artifact, run, workflow = provenance(record)
    if fault == "head": run["head_sha"] = SECOND
    elif fault == "repository": run["repository"]["full_name"] = "Other/repo"
    elif fault == "pr": run["pull_requests"] = [{"number": 8}]
    elif fault == "event": run["event"] = "workflow_dispatch"
    elif fault == "workflow": workflow["path"] = ".github/workflows/unrelated.yml"
    elif fault == "expired": artifact["expired"] = True
    elif fault == "run": artifact["workflow_run"]["id"] = 11
    elif fault == "attempt": record["attempt"] = 2
    elif fault == "digest": record["body_sha256"] = "wrong"
    elif fault == "action": record["action"] = "edited"
    elif fault == "before": record["before"] = SECOND
    else: record["raw_body"] = "Not allowed"
    with pytest.raises(gate.Unknown):
        gate.validate_record(record, artifact, run, workflow, repository=REPO, number=7, head=FIRST, default_head=gate.BOOTSTRAP_BASE)


def test_history_records_cannot_be_substituted_between_pull_requests(gate):
    _, first = capture(gate, event())
    first["number"] = 8
    with pytest.raises(gate.Unknown):
        capture(gate, event("synchronize", SECOND, "Changed", FIRST), {FIRST: first}, 11)


def test_no_first_workflow_time_or_content_revision_inference():
    path = ROOT / "scripts/check_pr_description_changed.py"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "userContentEdits" not in text
    assert "created_at" not in text


def test_return_to_an_earlier_head_is_unknown(gate):
    _, first = capture(gate, event())
    _, second = capture(gate, event("synchronize", SECOND, "Changed", FIRST), {FIRST: first}, 11)
    with pytest.raises(gate.Unknown, match="repeated|conflicting|ambiguous"):
        capture(gate, event("synchronize", FIRST, "Third description", SECOND), {FIRST: first, SECOND: second}, 12)


def test_unavailable_platform_history_is_not_a_first_push(gate):
    def unavailable(_head):
        raise gate.Unknown("platform unavailable")
    with pytest.raises(gate.Unknown):
        gate.evaluate(event(), unavailable, repository=REPO, run_id=10, attempt=1)


def test_identical_rerun_observation_remains_usable(gate):
    _, first = capture(gate, event())
    status, _ = capture(gate, event(), {FIRST: first}, 10)
    assert status == "BASELINE"


def test_candidate_run_cannot_supply_ordinary_trusted_history(gate):
    _, record = capture(gate, event())
    artifact, run, workflow = provenance(record)
    with pytest.raises(gate.Unknown, match="bootstrap"):
        gate.validate_record(record, artifact, run, workflow, repository=REPO, number=7, head=FIRST, default_head="c" * 40)
    run["event"] = "pull_request_target"
    assert gate.validate_record(record, artifact, run, workflow, repository=REPO, number=7, head=FIRST) == record


def zipped(record, name="description-history.json"):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, json.dumps(record))
    return result.getvalue()


@pytest.mark.parametrize("fault", ["wrong-member", "huge-record", "invalid-zip"])
def test_record_archive_is_bounded_and_not_extracted(gate, fault):
    _, record = capture(gate, event())
    raw = zipped(record)
    if fault == "wrong-member": raw = zipped(record, "../record.json")
    elif fault == "huge-record": raw = zipped({"body": "a" * 9000})
    else: raw = b"invalid zip"
    with pytest.raises(gate.Unknown):
        gate.read_archive(raw)


def test_real_archive_roundtrip_and_platform_lookup(gate, monkeypatch):
    _, record = capture(gate, event())
    artifact, run, workflow = provenance(record)
    artifact["id"] = 100
    def api(path):
        if "/actions/artifacts?" in path:
            assert f"name=pr-description-push-7-{FIRST}&" in path
            return {"artifacts": [artifact]}
        if "/actions/runs/10" in path: return run
        if "/actions/workflows/20" in path: return workflow
        if "/commits?per_page=1" in path: return [{"sha": gate.BOOTSTRAP_BASE}]
        raise AssertionError(path)
    monkeypatch.setattr(gate, "api", api)
    monkeypatch.setattr(gate, "gh", lambda path: zipped(record) if path.endswith("/100/zip") else pytest.fail(path))
    assert gate.History(REPO, 7)(FIRST) == record


def test_conflicting_observations_for_same_commit_are_unknown(gate, monkeypatch):
    _, first = capture(gate, event())
    other = copy.deepcopy(first)
    other["body_sha256"] = "0" * 64
    artifacts = [{"name": f"pr-description-push-7-{FIRST}", "id": index, "workflow_run": {"id": 10}} for index in (1, 2)]
    def api(path):
        if "/artifacts?" in path: return {"artifacts": artifacts}
        if "/workflows/" in path: return {"path": gate.WORKFLOW}
        return {"workflow_id": 20, "event": "pull_request_target", "repository": {"full_name": REPO}}
    monkeypatch.setattr(gate, "api", api)
    monkeypatch.setattr(gate, "gh", lambda path: zipped(first if path.endswith("/1/zip") else other))
    monkeypatch.setattr(gate, "validate_record", lambda record, *args, **kwargs: record)
    with pytest.raises(gate.Unknown, match="different observations"):
        gate.History(REPO, 7)(FIRST)


def test_historical_run_keeps_its_head_when_nested_pull_metadata_advances(gate):
    _, record = capture(gate, event())
    artifact, run, workflow = provenance(record)
    run["event"] = "pull_request_target"
    run["pull_requests"][0]["head"]["sha"] = SECOND
    run["pull_requests"][0]["base"]["sha"] = "c" * 40
    assert run["head_sha"] == FIRST
    assert gate.validate_record(record, artifact, run, workflow, repository=REPO, number=7, head=FIRST) == record
