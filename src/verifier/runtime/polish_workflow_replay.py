"""Replay selected preparation for Verifier Standard (VSTD) gate consumers.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
The consumer selects the exact policy contract separately. A carried report is
not authority. Replay establishes current selected checks, not historical
execution authenticity, polished status, human acceptance or publication rights.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from verifier.runtime.artifact_snapshot import Snapshot
from verifier.runtime import polish_workflow as workflow

CONTRACT_SCHEMA = "verifier-gates-workflow-preparation-contract-1"
FIELDS = (
    "schema_version policy_json policy_digest definition_json definition_digest "
    "quality_profile_json quality_profile_digest requirements_json "
    "requirements_digest base head definition_path"
)


def _selected(contract: dict[str, Any], name: str) -> bytes | None:
    text, expected = contract[name + "_json"], contract[name + "_digest"]
    if text is None and expected is None:
        return None
    if type(text) is not str:
        raise workflow.WorkflowError("selected " + name + " bytes required")
    raw = text.encode("utf-8")
    workflow._pin(raw, expected, name)
    return raw


def _stable_report(report: dict[str, Any]) -> dict[str, Any]:
    """Exclude only storage locations and executed temporary argument paths.

    Those fields remain in the original report. Fresh replay is the authority
    for current checks; this projection authenticates no previous execution.
    """
    projected = workflow._record(workflow.canonical(report))
    carried = projected.pop("report_digest", None)
    if workflow.digest(workflow.canonical(projected)) != carried:
        raise workflow.WorkflowError("preparation report digest differs")
    if (
        projected.get("schema_version") != workflow.REPORT_SCHEMA
        or projected.get("mode") != "CHECK_ONLY"
        or projected.get("status") != "PASS"
        or projected.get("polished") is not False
        or projected.get("promotable") is not False
        or projected.get("state") != "EXACT_INPUTS_RETAINED"
        or projected.get("resume", {}).get("requested") is not False
    ):
        raise workflow.WorkflowError(
            "fresh exact-input check-only preparation required"
        )
    if projected.get("bundle") is not None:
        projected["bundle"]["path"] = None
    if "quality" in projected:
        quality = projected["quality"]
        rows = [row for row in projected["stages"] if row["id"] == "quality"]
        if len(rows) != 1 or rows[0]["output_digest"] != workflow.digest(
            workflow.canonical(quality)
        ):
            raise workflow.WorkflowError("quality stage output binding differs")
        rows[0]["output_digest"] = None
        projected["quality"] = workflow._quality_projection(quality)
    return projected


def validate_workflow_preparation(
    raw: bytes,
    artifact_path: str | Path,
    snapshot: Snapshot,
    *,
    contract_bytes: bytes | None,
    expected_contract_digest: str | None,
    git_root: str | Path | None = None,
) -> dict[str, Any]:
    """Replay installed checks under separately selected exact contract bytes."""
    workflow._pin(contract_bytes, expected_contract_digest, "preparation contract")
    if contract_bytes is None:
        raise workflow.WorkflowError(
            "independently selected preparation contract required"
        )
    contract = workflow._record(contract_bytes)
    workflow._keys(contract, FIELDS)
    if contract["schema_version"] != CONTRACT_SCHEMA:
        raise workflow.WorkflowError("unsupported preparation replay contract")
    policy_raw = _selected(contract, "policy")
    if policy_raw is None:
        raise workflow.WorkflowError("preparation policy required")
    policy = workflow.load_policy(policy_raw, contract["policy_digest"])
    if snapshot.kind != "directory" or set(policy["input_paths"]) != set(
        snapshot.files
    ):
        raise workflow.WorkflowError(
            "preparation policy must bind the complete gate artifact"
        )
    definition = _selected(contract, "definition")
    quality = _selected(contract, "quality_profile")
    requirements = _selected(contract, "requirements")
    if (contract["base"] is None) != (contract["head"] is None):
        raise workflow.WorkflowError("exact base and head must be selected together")
    if contract["head"] is not None and git_root is None:
        raise workflow.WorkflowError(
            "selected committed analysis requires a Git object source"
        )
    if contract["definition_path"] is not None:
        workflow._name(contract["definition_path"])
        if definition is None or contract["head"] is None:
            raise workflow.WorkflowError(
                "committed definition selection requires bytes and exact head"
            )
    observed = workflow._record(raw)
    observed_view = _stable_report(observed)
    reproduced = workflow.prepare_workflow(
        artifact_path,
        policy_bytes=policy_raw,
        expected_policy_digest=contract["policy_digest"],
        definition_bytes=definition,
        quality_profile_bytes=quality,
        expected_quality_profile_digest=contract["quality_profile_digest"],
        requirements_bytes=requirements,
        expected_requirements_digest=contract["requirements_digest"],
        git_root=git_root,
        base=contract["base"],
        head=contract["head"],
        definition_path=contract["definition_path"],
    )
    if workflow.canonical(observed_view) != workflow.canonical(
        _stable_report(reproduced)
    ):
        raise workflow.WorkflowError(
            "preparation is stale, incomplete, forged or does not replay"
        )
    # The new workflow never waives the existing source/prose admission checks.
    from verifier.runtime.polish_prepare import prepare_artifact, validate_preparation

    legacy = prepare_artifact(artifact_path)
    validate_preparation(workflow.canonical(legacy), snapshot)
    return reproduced
