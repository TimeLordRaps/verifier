"""Independent pull request (PR) privacy and producer-eligibility guards.

Terminology: JavaScript Object Notation (JSON). No live services are used.
"""
from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = "Example/project"
HEAD = "a" * 40
BASE = "c" * 40


@pytest.fixture
def gate():
    spec = importlib.util.spec_from_file_location("independent_history", ROOT / "scripts/check_pr_description_changed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_raw_description_is_not_in_runner_printed_workflow_fields():
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-description.yml").read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            for value in [*step.get("env", {}).values(), step.get("run", "")]:
                assert "github.event.pull_request.body" not in str(value), "Untrusted body enters a runner-printed field"


def evidence(event_name, run_id, *, invalid=False):
    record = {"schema": "pr-description-event-1", "repository": REPO, "number": 7,
              "head": HEAD, "base": BASE, "before": None, "action": "opened",
              "body_sha256": "d" * 64, "run_id": run_id, "attempt": 1}
    if event_name == "pull_request":
        record["base"] = "fc2a20c68d01920eda7e4e1bf14dfbcb334a7634"
    if invalid:
        record["body_sha256"] = "malformed"
    artifact = {"id": run_id + 100, "name": f"pr-description-push-7-{HEAD}", "expired": False,
                "workflow_run": {"id": run_id, "head_sha": HEAD}}
    run = {"id": run_id, "run_attempt": 1, "event": event_name, "head_sha": HEAD,
           "repository": {"full_name": REPO}, "pull_requests": [{"number": 7}], "workflow_id": 20}
    return record, artifact, run


def install_platform(gate, monkeypatch, entries):
    records = {item[0]["run_id"]: item[0] for item in entries}
    runs = {item[2]["id"]: item[2] for item in entries}
    downloads = []

    def api(path):
        if "/actions/artifacts?" in path:
            return {"total_count": len(entries), "artifacts": [copy.deepcopy(item[1]) for item in entries]}
        if "/actions/runs/" in path:
            run_id = int(path.split("/actions/runs/")[1].split("/")[0])
            return copy.deepcopy(runs[run_id])
        if "/actions/workflows/20" in path:
            return {"id": 20, "path": ".github/workflows/pr-description.yml"}
        if path.endswith("/commits?per_page=1"):
            return [{"sha": BASE}]
        raise AssertionError("Unexpected platform route")

    def download(path):
        artifact_id = int(path.split("/actions/artifacts/")[1].split("/")[0])
        run_id = artifact_id - 100
        downloads.append(run_id)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("description-history.json", json.dumps(records[run_id]))
        return output.getvalue()

    monkeypatch.setattr(gate, "api", api)
    monkeypatch.setattr(gate, "gh", download)
    return downloads


def test_ordinary_target_record_is_usable(gate, monkeypatch):
    target = evidence("pull_request_target", 12)
    install_platform(gate, monkeypatch, [target])
    assert gate.History(REPO, 7)(HEAD) == target[0]


@pytest.mark.parametrize("candidate_first", [True, False])
def test_ineligible_candidate_cannot_deny_eligible_target(gate, monkeypatch, candidate_first):
    candidate = evidence("pull_request", 11)
    target = evidence("pull_request_target", 12)
    entries = [candidate, target] if candidate_first else [target, candidate]
    downloads = install_platform(gate, monkeypatch, entries)
    assert gate.History(REPO, 7)(HEAD) == target[0]
    assert 11 not in downloads, "Ineligible producer payload should not be downloaded or parsed"


def test_ineligible_candidate_alone_does_not_become_trusted(gate, monkeypatch):
    install_platform(gate, monkeypatch, [evidence("pull_request", 11)])
    with pytest.raises(gate.Unknown):
        gate.History(REPO, 7)(HEAD)


def test_malformed_eligible_target_stays_unknown(gate, monkeypatch):
    install_platform(gate, monkeypatch, [evidence("pull_request_target", 12, invalid=True)])
    with pytest.raises(gate.Unknown):
        gate.History(REPO, 7)(HEAD)


@pytest.mark.parametrize("producer", ["workflow_dispatch", "unrelated-workflow"])
def test_other_producers_are_excluded_before_payload_download(gate, monkeypatch, producer):
    foreign = evidence("workflow_dispatch" if producer == "workflow_dispatch" else "pull_request_target", 11)
    target = evidence("pull_request_target", 12)
    if producer == "unrelated-workflow":
        foreign[2]["workflow_id"] = 21
    downloads = install_platform(gate, monkeypatch, [foreign, target])
    platform_api = gate.api

    def api(path):
        if "/actions/workflows/21" in path:
            return {"id": 21, "path": ".github/workflows/unrelated.yml"}
        return platform_api(path)

    monkeypatch.setattr(gate, "api", api)
    assert gate.History(REPO, 7)(HEAD) == target[0]
    assert 11 not in downloads


# Bind the independently authored metadata oracle to these identical native
# fixtures without importing private evidence or changing its function body.
fixtures = SimpleNamespace(evidence=evidence, install_platform=install_platform, REPO=REPO, HEAD=HEAD)


@pytest.mark.parametrize("missing", ["workflow-path", "event", "repository"])
def test_missing_eligibility_metadata_remains_unknown(gate, monkeypatch, missing):
    uncertain = fixtures.evidence("pull_request_target", 11)
    valid = fixtures.evidence("pull_request_target", 12)
    uncertain[2]["workflow_id"] = 21
    if missing == "event":
        uncertain[2].pop("event")
    elif missing == "repository":
        uncertain[2].pop("repository")
    fixtures.install_platform(gate, monkeypatch, [uncertain, valid])
    platform_api = gate.api

    def api(path):
        if "/actions/workflows/21" in path:
            value = {"id": 21, "path": ".github/workflows/pr-description.yml"}
            if missing == "workflow-path":
                value.pop("path")
            return value
        return platform_api(path)

    monkeypatch.setattr(gate, "api", api)
    with pytest.raises(gate.Unknown):
        gate.History(fixtures.REPO, 7)(fixtures.HEAD)
