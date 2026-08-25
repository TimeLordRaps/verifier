"""CLI tests for the verdict-neutral experimental-workflow surface."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from verifier.experimental_workflow import seal_manifest
from verifier.runtime.public_cli import main


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "github_verdict_neutrality" / "experiment.json"
SNAPSHOT = ROOT / "examples" / "experimental_workflow" / "github_snapshot.json"


def test_experiment_validate_reports_exact_non_verdict_scope(capsys) -> None:
    assert main(["experiment", "validate", str(MANIFEST), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "VALID"
    assert result["repository_artifacts"] == "NOT_APPLICABLE"
    assert result["vstd_verdict_granted"] is False
    assert result["experiment"]["id"] == "experiment-github-verdict-neutrality"


def test_experiment_validate_rejects_tampered_digest(tmp_path: Path, capsys) -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["experiment"]["question"] = "Substituted question"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["experiment", "validate", str(path), "--json"]) == 1
    assert "manifest_digest" in capsys.readouterr().err


def test_experiment_validate_does_not_skip_repository_artifacts(
    tmp_path: Path, capsys
) -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload.pop("manifest_digest")
    payload["artifacts"].append(
        {
            "id": "artifact-repository-evidence",
            "role": "repository-evidence",
            "media_type": "text/plain",
            "digest": "sha256:" + hashlib.sha256(b"evidence").hexdigest(),
            "locator": "repo:evidence.txt",
        }
    )
    path = tmp_path / "unchecked.json"
    path.write_text(json.dumps(seal_manifest(payload)), encoding="utf-8")

    assert main(["experiment", "validate", str(path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "VALID_WITH_UNCHECKED_REPOSITORY_ARTIFACTS"
    assert result["repository_artifacts"] == "NOT_CHECKED"
    assert result["vstd_verdict_granted"] is False


def test_experiment_github_events_remain_verdict_neutral(capsys) -> None:
    assert main(["experiment", "github-events", str(SNAPSHOT), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["event_count"] == 5
    assert result["verification_effects"] == ["NONE"]
    assert result["vstd_verdicts_granted"] == 0
