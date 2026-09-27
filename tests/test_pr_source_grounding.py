"""Source-grounded pull request (PR) coverage, independent omission controls."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("source_gate", ROOT / "scripts/check_pr_description.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, timeout=20).strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init")
    git(tmp_path, "config", "user.name", "Fixture")
    git(tmp_path, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(tmp_path, "config", "commit.gpgsign", "false")
    source = tmp_path / "src/verifier"
    source.mkdir(parents=True)
    (source / "feature.py").write_text("def existing():\n    return 1\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "baseline")
    base = git(tmp_path, "rev-parse", "HEAD")
    (source / "feature.py").write_text("def existing():\n    return 2\n\ndef admission():\n    return False\n", encoding="utf-8")
    return tmp_path, base


def body_for(inventory):
    rows = [{**row, "summary": "Reject admission until independent evidence is supplied.",
             "limits": "This record does not establish external authorization."}
            for row in inventory["files"]]
    return "```vstd-source-features\n" + json.dumps({**inventory, "files": rows}) + "\n```"


def check(repo, body):
    root, base = repo
    findings = []
    gate.check_source_grounding(body, findings, root=root, base=base)
    return findings


def test_changed_function_cannot_hide_behind_domain_names(repo):
    assert check(repo, "ACTOR OWNER IDENTITY ROLE COLLECTIVE HUMAN: all described")


def test_exact_bound_coverage_passes(repo):
    inventory = gate.source_feature_inventory(repo[0], repo[1])
    assert inventory["files"][0]["symbols"] == ["admission", "existing"]
    assert check(repo, body_for(inventory)) == []


def manifest_body(repo, inventory):
    root, _ = repo
    rows = [{**row, "summary": "Bind the changed feature behavior to retained inputs.",
             "limits": "This file alone does not establish external authorization."}
            for row in inventory["files"]]
    document = {"base": inventory["base"], "files": rows}
    path = root / "docs/PR_SOURCE_FEATURES.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    block = {"base": inventory["base"], "target": inventory["target"],
             "manifest": {"path": "docs/PR_SOURCE_FEATURES.json",
                          "sha256": hashlib.sha256(raw).hexdigest()}}
    return "```vstd-source-features\n" + json.dumps(block) + "\n```"


def test_committed_manifest_mode_keeps_complete_source_coverage(repo):
    inventory = gate.source_feature_inventory(repo[0], repo[1])
    body = manifest_body(repo, inventory)
    assert check(repo, body) == []
    manifest = repo[0] / "docs/PR_SOURCE_FEATURES.json"
    manifest.write_text(manifest.read_text(encoding="utf-8").replace(
        "Bind the changed feature behavior", "Forged summary"), encoding="utf-8")
    assert check(repo, body)


def test_manifest_rows_still_reject_source_omission(repo):
    inventory = gate.source_feature_inventory(repo[0], repo[1])
    body = manifest_body(repo, inventory)
    manifest = repo[0] / "docs/PR_SOURCE_FEATURES.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["files"] = []
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    manifest.write_bytes(raw)
    block = json.loads(body.split("\n", 1)[1].rsplit("\n", 1)[0])
    block["manifest"]["sha256"] = hashlib.sha256(raw).hexdigest()
    assert any("missing, stale or extraneous" in finding for finding in check(
        repo, "```vstd-source-features\n" + json.dumps(block) + "\n```"))


def test_manifest_commit_mode_ignores_later_uncommitted_edits(repo):
    root, base = repo
    inventory = gate.source_feature_inventory(root, base)
    body = manifest_body(repo, inventory)
    git(root, "add", ".")
    git(root, "commit", "-m", "candidate with source manifest")
    target = git(root, "rev-parse", "HEAD")
    body = body.replace(inventory["target"], target)
    findings = []
    gate.check_source_grounding(body, findings, root=root, base=base, target=target)
    assert findings == []
    (root / "docs/PR_SOURCE_FEATURES.json").write_text("{}", encoding="utf-8")
    (root / "src/verifier/feature.py").write_text("def changed(): return True\n", encoding="utf-8")
    findings = []
    gate.check_source_grounding(body, findings, root=root, base=base, target=target)
    assert findings == []
    assert check(repo, body)


@pytest.mark.parametrize("mutation", ["missing_file", "missing_symbol", "stale_digest", "empty_summary", "duplicate_file", "wrong_base", "wrong_target", "extra_file"])
def test_coverage_mutations_are_rejected(repo, mutation):
    inventory = gate.source_feature_inventory(repo[0], repo[1])
    data = json.loads(body_for(inventory).split("\n", 1)[1].rsplit("\n", 1)[0])
    if mutation == "missing_file": data["files"] = []
    elif mutation == "missing_symbol": data["files"][0]["symbols"].remove("admission")
    elif mutation == "stale_digest": data["files"][0]["sha256"] = "0" * 64
    elif mutation == "empty_summary": data["files"][0]["summary"] = ""
    elif mutation == "duplicate_file": data["files"].append(data["files"][0])
    elif mutation == "wrong_base": data["base"] = "0" * 40
    elif mutation == "wrong_target": data["target"] = "0" * 40
    elif mutation == "extra_file": data["files"].append({**data["files"][0], "path": "src/verifier/imaginary.py"})
    assert check(repo, "```vstd-source-features\n" + json.dumps(data) + "\n```")


def test_untracked_source_and_declared_domains_are_inventoried(repo):
    root, base = repo
    (root / "src/verifier/new.py").write_text("class Role:\n    def admit(self):\n        return False\n")
    (root / "src/verifier/contract.json").write_text('{"domain":"HUMAN"}')
    paths = {r["path"]: r for r in gate.source_feature_inventory(root, base)["files"]}
    assert paths["src/verifier/new.py"]["symbols"] == ["Role", "Role.admit"]
    assert "src/verifier/contract.json" in paths


def test_deleted_source_requires_explicit_coverage(repo):
    root, base = repo
    (root / "src/verifier/feature.py").unlink()
    inventory = gate.source_feature_inventory(root, base)
    assert inventory["files"] == [{"path": "src/verifier/feature.py", "sha256": None, "symbols": ["existing"]}]
    assert check(repo, body_for(inventory)) == []


def test_commit_mode_excludes_later_uncommitted_source(repo):
    root, base = repo
    git(root, "add", ".")
    git(root, "commit", "-m", "candidate")
    target = git(root, "rev-parse", "HEAD")
    frozen = gate.source_feature_inventory(root, base, target)
    (root / "src/verifier/later.py").write_text("def later(): return True\n")
    assert gate.source_feature_inventory(root, base, target) == frozen
    assert len(gate.source_feature_inventory(root, base)["files"]) == 2


def test_duplicate_json_keys_and_multiple_blocks_fail(repo):
    inventory = gate.source_feature_inventory(repo[0], repo[1])
    body = body_for(inventory)
    assert check(repo, body + "\n" + body)
    assert check(repo, body.replace('"base":', '"base":"forged", "base":', 1))


def test_unimplemented_accountability_domain_cannot_be_omitted(tmp_path, monkeypatch):
    source = tmp_path / "verifier/core"
    source.mkdir(parents=True)
    (source / "profile_obligations.py").write_text(
        'rows = [_domain_rows("ACTOR", 1, ()), _domain_rows("HUMAN", 1, ())]\n')
    monkeypatch.setattr(gate, "SOURCE", tmp_path)
    findings = []
    gate.check_declared_domains("ACTOR adapter is present", findings)
    assert any("HUMAN" in finding for finding in findings)
    findings = []
    gate.check_declared_domains("ACTOR implemented; HUMAN declared, coverage unknown", findings)
    assert findings == []


def test_release_tooling_cannot_escape_source_coverage(repo):
    root, base = repo
    for name, content in [("scripts/publish.py", "def release(): return False\n"),
                          (".github/workflows/release.yml", "name: guarded release\n"),
                          ("pyproject.toml", "[project]\nname='fixture'\n")]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    paths = {row["path"] for row in gate.source_feature_inventory(root, base)["files"]}
    assert {"scripts/publish.py", ".github/workflows/release.yml", "pyproject.toml"} <= paths
