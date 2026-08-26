"""Terminology: line feed (LF); zero-identity/zero-knowledge (ZIZK).

Adversarial tests for the non-normative experimental-workflow profile."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

from verifier.experimental_workflow import (
    GitHubAdapterError,
    WorkflowProfileError,
    github_snapshot_to_events,
    load_manifest,
    seal_manifest,
    validate_manifest,
    verify_repo_artifacts,
    workflow_manifest_schema,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "experimental_workflow"
EXPERIMENT_MANIFEST = (
    ROOT / "experiments" / "github_verdict_neutrality" / "experiment.json"
)
ARTIFACT_FIRST_MECHANISMS_MANIFEST = (
    ROOT / "experiments" / "artifact_first_mechanisms" / "experiment.json"
)


def _example_payload() -> dict[str, object]:
    return json.loads(EXPERIMENT_MANIFEST.read_text(encoding="utf-8"))


def _github_snapshot() -> dict[str, object]:
    return json.loads((EXAMPLE / "github_snapshot.json").read_text(encoding="utf-8"))


def _add_mapped_result(payload: dict[str, object], verdict: str) -> None:
    artifacts = payload["artifacts"]
    actions = payload["actions"]
    native_results = payload["native_results"]
    assert isinstance(artifacts, list)
    assert isinstance(actions, list) and isinstance(actions[0], dict)
    assert isinstance(native_results, list)
    artifacts.append(
        {
            "id": "artifact-vstd-receipt",
            "role": "mapped-vstd-receipt",
            "media_type": "application/json",
            "digest": "sha256:" + "3" * 64,
            "locator": "artifact:vstd-receipt",
        }
    )
    native_results.append(
        {
            "id": "result-mapped",
            "action_id": actions[0]["id"],
            "verifier": {
                "kind": "domain-verifier",
                "name": "bounded-example",
                "version": "1",
                "coordinate": "urn:example:bounded-verifier",
            },
            "native_status": "INDETERMINATE",
            "result_artifact_id": None,
            "mapping": {
                "status": "MAPPED",
                "vstd_verdict": verdict,
                "mapping_profile": "urn:example:vstd-mapping:1",
                "receipt_artifact_id": "artifact-vstd-receipt",
                "reason": "A separate receipt records the bounded mapping.",
            },
        }
    )
    actions[0]["native_result_ids"] = ["result-mapped"]


def test_checked_in_manifests_validate_and_match_schema() -> None:
    schema = workflow_manifest_schema()
    payload = load_manifest(EXPERIMENT_MANIFEST)
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_artifact_first_mechanism_manifest_preserves_dual_causal_boundary() -> None:
    payload = load_manifest(ARTIFACT_FIRST_MECHANISMS_MANIFEST)
    verify_repo_artifacts(payload, ROOT)

    assert payload["experiment"]["id"] == "experiment-artifact-first-mechanisms"
    assert "governing" in payload["experiment"]["title"]

    artifacts = {item["id"]: item for item in payload["artifacts"]}
    assert artifacts["artifact-zk-receipt"]["locator"].endswith(
        "recorded-proof/receipt.msgpack"
    )
    assert artifacts["artifact-zk-public-envelope"]["locator"].endswith(
        "recorded-proof/public.json"
    )
    assert artifacts["artifact-zk-self-test"]["locator"].endswith(
        "recorded-proof/self-test-results.json"
    )

    hypotheses = {item["id"]: item for item in payload["hypotheses"]}
    assert hypotheses["hypothesis-artifact-first-zero-actor-trust"]["state"] == "OPEN"
    assert hypotheses["hypothesis-contextual-actor-artifact-roles"]["state"] == "OPEN"
    assert hypotheses["hypothesis-rust-genetic-backtrace"]["state"] == "OPEN"
    assert hypotheses["hypothesis-dual-causal-propagation"]["state"] == "OPEN"

    adaptation = payload["adaptations"][0]
    assert "standard/LADDER.md section 1.1" in adaptation["decision"]
    assert "parent-to-child artifact support" in adaptation["decision"]
    assert "child-to-parent Rust" in adaptation["decision"]

    horizons = {item["id"]: item["status"] for item in payload["horizons"]}
    assert horizons["horizon-contextual-role-protocol"] == "UNKNOWN"
    assert horizons["horizon-rust-genetic-backtrace"] == "UNKNOWN"
    assert horizons["horizon-forward-artifact-trust"] == "UNKNOWN"


def test_manifest_bound_text_artifacts_use_repository_lf_bytes() -> None:
    payload = load_manifest(ARTIFACT_FIRST_MECHANISMS_MANIFEST)
    for artifact in payload["artifacts"]:
        if artifact["media_type"] != "text/markdown":
            continue
        locator = artifact["locator"]
        assert locator.startswith("repo:")
        data = (ROOT / locator.removeprefix("repo:")).read_bytes()
        assert b"\r\n" not in data, f"{locator} must match Git's LF-normalized bytes"


def test_checked_in_schema_is_generated_from_one_source() -> None:
    checked_in = json.loads(
        (ROOT / "docs" / "profiles" / "experimental-workflow.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert checked_in == workflow_manifest_schema()


def test_manifest_digest_detects_semantic_tampering() -> None:
    payload = _example_payload()
    experiment = payload["experiment"]
    assert isinstance(experiment, dict)
    experiment["question"] = "A substituted question"
    with pytest.raises(WorkflowProfileError, match="canonical stable payload"):
        validate_manifest(payload)


def test_seal_manifest_does_not_mutate_caller() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    original = copy.deepcopy(payload)
    sealed = seal_manifest(payload)
    assert payload == original
    assert sealed["manifest_digest"].startswith("sha256:")


@pytest.mark.parametrize("value", [-1, 1.5, True])
def test_budget_rejects_negative_float_and_boolean_limits(value: object) -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    budgets = payload["budgets"]
    assert isinstance(budgets, list) and isinstance(budgets[0], dict)
    budgets[0]["limit"] = value
    with pytest.raises(WorkflowProfileError):
        seal_manifest(payload)


def test_consumed_work_cannot_exceed_bound() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    budgets = payload["budgets"]
    assert isinstance(budgets, list) and isinstance(budgets[0], dict)
    budgets[0]["consumed"] = budgets[0]["limit"] + 1
    with pytest.raises(WorkflowProfileError, match="exceeds"):
        seal_manifest(payload)


def test_every_selected_action_requires_a_budget() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    actions = payload["actions"]
    assert isinstance(actions, list) and isinstance(actions[0], dict)
    actions[0]["budget_ids"] = []
    with pytest.raises(WorkflowProfileError, match="bind at least one budget"):
        seal_manifest(payload)


def test_action_dependency_cycles_fail_closed() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    actions = payload["actions"]
    assert isinstance(actions, list) and isinstance(actions[0], dict)
    actions[0]["depends_on"] = [actions[0]["id"]]
    with pytest.raises(WorkflowProfileError, match="dependency cycle"):
        seal_manifest(payload)


@pytest.mark.parametrize(
    "locator",
    [
        "C" + ":\\private\\result.json",
        "/" + "home/person/result.json",
        "repo:../private/result.json",
        "repo:folder\\result.json",
    ],
)
def test_nonportable_or_escaping_artifact_locators_are_rejected(locator: str) -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    artifacts.append(
        {
            "id": "artifact-bad-locator",
            "role": "test",
            "media_type": "application/json",
            "digest": "sha256:" + "4" * 64,
            "locator": locator,
        }
    )
    with pytest.raises(WorkflowProfileError):
        seal_manifest(payload)


def test_not_evaluated_mapping_cannot_smuggle_a_verdict() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    _add_mapped_result(payload, "PASS")
    native_results = payload["native_results"]
    assert isinstance(native_results, list) and isinstance(native_results[0], dict)
    mapping = native_results[0]["mapping"]
    assert isinstance(mapping, dict)
    mapping["status"] = "NOT_EVALUATED"
    with pytest.raises(WorkflowProfileError, match="cannot carry"):
        seal_manifest(payload)


@pytest.mark.parametrize("verdict", ["UNKNOWN", "CONFLICTED"])
def test_uncertain_mapped_verdicts_remain_representable(verdict: str) -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    _add_mapped_result(payload, verdict)
    sealed = seal_manifest(payload)
    result = sealed["native_results"][0]
    assert result["mapping"]["vstd_verdict"] == verdict


def test_successful_workflow_and_merge_have_no_verification_effect() -> None:
    events = github_snapshot_to_events(_github_snapshot())
    assert len(events) == 5
    assert {event["verification_effect"] for event in events} == {"NONE"}
    assert any(event["native_state"] == "completed/success" for event in events)
    assert any(event["native_state"] == "closed/MERGED" for event in events)
    assert all("vstd_verdict" not in event for event in events)


def test_platform_event_verification_upgrade_is_rejected() -> None:
    payload = _example_payload()
    payload.pop("manifest_digest")
    events = payload["workflow_events"]
    assert isinstance(events, list) and isinstance(events[0], dict)
    events[0]["verification_effect"] = "PASS"
    with pytest.raises(WorkflowProfileError, match="cannot grant"):
        seal_manifest(payload)


def test_github_adapter_rejects_unknown_fields_instead_of_guessing() -> None:
    snapshot = _github_snapshot()
    snapshot["deployment_statuses"] = []
    with pytest.raises(GitHubAdapterError, match="unsupported fields"):
        github_snapshot_to_events(snapshot)


def test_github_adapter_is_deterministic_and_matches_specimen() -> None:
    events = github_snapshot_to_events(_github_snapshot())
    manifest = load_manifest(EXPERIMENT_MANIFEST)
    assert list(events) == manifest["workflow_events"]
    assert events == github_snapshot_to_events(_github_snapshot())


def test_repo_artifact_binding_detects_substitution(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_bytes(b"original")
    payload = _example_payload()
    payload.pop("manifest_digest")
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    artifacts.append(
        {
            "id": "artifact-repo-test",
            "role": "test-evidence",
            "media_type": "text/plain",
            "digest": "sha256:" + hashlib.sha256(b"original").hexdigest(),
            "locator": "repo:evidence.txt",
        }
    )
    sealed = seal_manifest(payload)
    verify_repo_artifacts(sealed, tmp_path)
    artifact.write_bytes(b"substituted")
    with pytest.raises(WorkflowProfileError, match="does not match"):
        verify_repo_artifacts(sealed, tmp_path)


def test_indexed_repository_artifacts_match_manifest() -> None:
    payload = load_manifest(EXPERIMENT_MANIFEST)
    verify_repo_artifacts(payload, ROOT)


def test_experiment_index_is_current() -> None:
    spec = importlib.util.spec_from_file_location(
        "build_experiment_index", ROOT / "scripts" / "build_experiment_index.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = module.render(module.discover(ROOT))
    assert (ROOT / "experiments" / "INDEX.md").read_text(encoding="utf-8") == expected
