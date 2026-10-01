"""Terminology: pull request (PR); JavaScript Object Notation (JSON).

Exact-head and workflow trust controls.
"""
from __future__ import annotations

import importlib.util
import ast
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BOOTSTRAP_BASE = "fc2a20c68d01920eda7e4e1bf14dfbcb334a7634"


@pytest.fixture
def gate():
    path = ROOT / "scripts/check_pr_description.py"
    spec = importlib.util.spec_from_file_location("description_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("label", ["Current head", "Current signed head"])
def test_existing_head_only_contract_needs_no_new_schema(gate, label, monkeypatch):
    monkeypatch.setattr(gate, "tracked_files", lambda *_: pytest.fail("No optional count was claimed"))
    assert gate.findings(f"{label}: `{HEAD}`\nA bounded scanner repair.", HEAD, "Owner/repo") == []


@pytest.mark.parametrize("body", ["No head", "Current head: " + "b" * 40,
                                 "Current head: " + HEAD + "\nCurrent signed head: " + "b" * 40])
def test_missing_or_conflicting_head_is_rejected(gate, body):
    assert gate.findings(body, HEAD, "Owner/repo")


@pytest.mark.parametrize("stated,valid", [("1,234", True), ("1234", True), ("1233", False)])
def test_any_claimed_inventory_must_match(gate, monkeypatch, stated, valid):
    monkeypatch.setattr(gate, "tracked_files", lambda *_: 1234)
    assert bool(gate.findings(f"Current head: {HEAD}\ntracked inventory is {stated} files", HEAD, "Owner/repo")) is not valid


@pytest.mark.parametrize("fault", ["truncated", "missing-truncation", "missing-tree", "malformed", "platform-error"])
def test_incomplete_platform_tree_is_unknown(gate, monkeypatch, fault):
    payload = {"truncated": False, "tree": [{"type": "blob"}]}
    code = 0
    if fault == "truncated": payload["truncated"] = True
    elif fault == "missing-truncation": payload.pop("truncated")
    elif fault == "missing-tree": payload.pop("tree")
    elif fault == "platform-error": code = 1
    raw = b"not JSON" if fault == "malformed" else json.dumps(payload).encode()
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, code, raw))
    with pytest.raises(gate.Unanswered):
        gate.tracked_files("Owner/repo", HEAD)


def test_tree_counts_blobs_and_submodules_without_candidate_execution(gate, monkeypatch):
    payload = {"truncated": False, "tree": [{"type": kind} for kind in ("tree", "blob", "blob", "commit")]}
    calls = []
    def query(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode())
    monkeypatch.setattr(gate.subprocess, "run", query)
    assert gate.tracked_files("Owner/repo", HEAD) == 3
    assert calls == [["gh", "api", f"repos/Owner/repo/git/trees/{HEAD}?recursive=1"]]


def test_workflow_uses_exact_events_and_read_only_permissions():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-description.yml").read_text(encoding="utf-8"))
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"pull_request", "pull_request_target"}
    expected = {"opened", "reopened", "synchronize", "edited", "ready_for_review"}
    assert all(set(value["types"]) == expected for value in events.values())
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"describes-head", "changed-since-last-push"}
    for key, job in workflow["jobs"].items():
        # Ordinary candidate events cannot emit skipped-success required names.
        assert "pull_request_target" in job["name"] and BOOTSTRAP_BASE in job["name"]
        assert "non-authoritative" in job["name"]
        assert job["timeout-minutes"] <= 5
        assert all(value == "read" for value in job.get("permissions", {}).values())
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
                ref = step["with"]["ref"]
                assert "pull_request_target" in ref and "default_branch" in ref
            if "run" in step:
                assert "${{" not in step["run"]
            assert all("github.event.pull_request.body" not in str(value) for value in step.get("env", {}).values())
        admission = next(step for step in job["steps"] if step.get("id") == "admission")
        assert "ls-remote" in admission["run"] and "ls-tree" in admission["run"]
        assert BOOTSTRAP_BASE in admission["env"]["BOOTSTRAP_BASE"]
        assert all("admission.outputs.allowed" in step.get("if", "") for step in job["steps"] if step.get("id") == "check")
    history = workflow["jobs"]["changed-since-last-push"]
    assert history["concurrency"]["cancel-in-progress"] is False
    uploads = [s for s in history["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 1
    assert "always()" in uploads[0]["if"]
    assert "opened" in uploads[0]["if"] and "synchronize" in uploads[0]["if"]


def expression_value(expression, event, base):
    source = expression.removeprefix("${{").removesuffix("}}").strip()
    replacements = {"github.event_name": event, "github.event.pull_request.base.sha": base,
                    "github.event.pull_request.head.sha": HEAD, "github.event.repository.default_branch": "main"}
    for key in sorted(replacements, key=len, reverse=True):
        source = source.replace(key, repr(replacements[key]))
    source = source.replace("&&", " and ").replace("||", " or ")
    parsed = ast.parse(source, mode="eval")
    assert all(isinstance(node, (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.Constant)) for node in ast.walk(parsed))
    return eval(compile(parsed, "workflow-expression", "eval"), {"__builtins__": {}})


@pytest.mark.parametrize("event,base,required,checkout", [
    ("pull_request", BOOTSTRAP_BASE, True, HEAD),
    ("pull_request", "c" * 40, False, "main"),
    ("pull_request_target", BOOTSTRAP_BASE, True, "main"),
    ("pull_request_target", "c" * 40, True, "main"),
])
def test_workflow_authority_truth_table(event, base, required, checkout):
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-description.yml").read_text(encoding="utf-8"))
    for key, job in workflow["jobs"].items():
        assert (expression_value(job["name"], event, base) == key) is required
        step = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert expression_value(step["with"]["ref"], event, base) == checkout


@pytest.mark.parametrize("fault", [None, "head", "repo", "body-type", "missing-pull", "malformed"])
def test_event_file_input_keeps_untrusted_body_out_of_diagnostics(gate, tmp_path, capsys, fault):
    marker = "synthetic-private-description"
    payload = {"repository": {"full_name": "Owner/repo"}, "pull_request": {"head": {"sha": HEAD},
               "body": f"Current head: {HEAD}\n{marker}"}}
    if fault == "head": payload["pull_request"]["head"]["sha"] = "b" * 40
    elif fault == "repo": payload["repository"]["full_name"] = "Other/repo"
    elif fault == "body-type": payload["pull_request"]["body"] = {"value": marker}
    elif fault == "missing-pull": payload.pop("pull_request")
    path = tmp_path / "event.json"
    path.write_text("invalid " + marker if fault == "malformed" else json.dumps(payload), encoding="utf-8")
    assert gate.main(["--repo", "Owner/repo", "--commit", HEAD, "--event", str(path)]) == int(fault is not None)
    output = capsys.readouterr()
    assert marker not in output.out + output.err
