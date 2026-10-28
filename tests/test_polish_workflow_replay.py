"""Independent selections and adversarial downstream preparation replay controls.

Terminology: command-line interface (CLI); JavaScript Object Notation (JSON).
These controls establish bounded current checks, not execution authenticity.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from verifier.runtime import polish_workflow as workflow
from verifier.runtime import gates
from verifier.runtime.polish_workflow_replay import CONTRACT_SCHEMA
from verifier.runtime.public_cli import main


def fixture(root: Path) -> tuple[dict, bytes, str]:
    root.mkdir()
    (root / "demo.py").write_bytes(b"def increment(value):\n    return value + 1\n")
    selected = {"bind-inputs", "validate-definitions", "quality", "retain-bundle"}
    policy = {
        "schema_version": workflow.POLICY_SCHEMA,
        "input_paths": ["demo.py"],
        "stages": [
            {
                "id": row["id"],
                "selected": row["id"] in selected,
                "required": row["id"] in selected,
                "depends_on": row["depends_on"],
            }
            for row in workflow.STAGES
        ],
        "bounds": {"max_files": 8, "max_file_bytes": 8192, "max_total_bytes": 65536},
    }
    profile = {
        "schema_version": "verifier-quality-profile-1",
        "sources": ["demo.py"],
        "stages": [
            {
                "id": name,
                "selected": name == "comment-format",
                "required": name == "comment-format",
                "backend": (
                    "builtin-managed-python-comments-1"
                    if name == "comment-format"
                    else None
                ),
                "tool": None,
                "config": None,
            }
            for name in ("comment-format", "lint", "pretty-format")
        ],
        "timeout_seconds": 2,
        "max_output_bytes": 4096,
    }
    policy_raw, profile_raw = workflow.canonical(policy), workflow.canonical(profile)
    report = workflow.prepare_workflow(
        root,
        policy_bytes=policy_raw,
        expected_policy_digest=workflow.digest(policy_raw),
        quality_profile_bytes=profile_raw,
        expected_quality_profile_digest=workflow.digest(profile_raw),
    )
    assert report["status"] == "PASS" and report["state"] == "EXACT_INPUTS_RETAINED"
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "policy_json": policy_raw.decode(),
        "policy_digest": workflow.digest(policy_raw),
        "definition_json": None,
        "definition_digest": None,
        "quality_profile_json": profile_raw.decode(),
        "quality_profile_digest": workflow.digest(profile_raw),
        "requirements_json": None,
        "requirements_digest": None,
        "base": None,
        "head": None,
        "definition_path": None,
    }
    raw = workflow.canonical(contract)
    return report, raw, workflow.digest(raw)


def run(root: Path, report: dict, contract: bytes | None, pin: str | None) -> dict:
    return gates.run_gates(
        root,
        polish_report_bytes=workflow.canonical(report),
        preparation_contract_bytes=contract,
        expected_preparation_contract_digest=pin,
    )


def test_workflow_replays_current_checks_with_separately_selected_contract(
    tmp_path,
) -> None:
    root = tmp_path / "source"
    report, contract, pin = fixture(root)
    clearance = run(root, report, contract, pin)
    assert clearance["schema_version"] == "verifier-gates-clearance-3"
    assert clearance["coverage"]["preparation_status"] == "PASS"
    assert clearance["status"] == "PASS" and clearance["clearance"] == "CLEAR"
    assert (
        clearance["polished"] is False
        and clearance["execution_authentication"] == "NOT_ESTABLISHED"
    )
    assert (
        gates.validate_clearance(
            workflow.canonical(clearance),
            root,
            expected_preparation_contract_bytes=contract,
            expected_preparation_contract_digest=pin,
        )
        == clearance
    )
    with pytest.raises(ValueError, match="independently selected"):
        gates.validate_clearance(workflow.canonical(clearance), root)


@pytest.mark.parametrize(
    "change",
    [
        "missing-contract",
        "wrong-pin",
        "changed-policy",
        "changed-profile",
        "stale-source",
        "extra-source",
        "forged-stage",
        "forged-mode",
        "invented-polished",
        "unknown-field",
    ],
)
def test_missing_changed_or_forged_preparation_never_clears(tmp_path, change) -> None:
    root = tmp_path / "source"
    report, contract, pin = fixture(root)
    if change == "missing-contract":
        contract = pin = None
    elif change == "wrong-pin":
        pin = "0" * 64
    elif change in {"changed-policy", "changed-profile"}:
        value = json.loads(contract)
        key = "policy" if change == "changed-policy" else "quality_profile"
        value[key + "_json"] += " "
        value[key + "_digest"] = workflow.digest(value[key + "_json"].encode())
        contract = workflow.canonical(value)
        pin = workflow.digest(contract)
    elif change == "stale-source":
        (root / "demo.py").write_bytes(b"def increment(value):\n    return value + 2\n")
    elif change == "extra-source":
        (root / "extra.py").write_bytes(
            b"raise RuntimeError('candidate must not execute')\n"
        )
    else:
        report = copy.deepcopy(report)
        if change == "forged-stage":
            report["stages"][0]["output_digest"] = "0" * 64
        elif change == "forged-mode":
            report["mode"] = "APPLY"
        elif change == "invented-polished":
            report["polished"] = True
        else:
            report["human_acceptance"] = "invented"
        report.pop("report_digest")
        report["report_digest"] = workflow.digest(workflow.canonical(report))
    rejected = run(root, report, contract, pin)
    assert rejected["coverage"]["preparation_status"] == "FAIL"
    assert rejected["status"] == "FAIL" and rejected["clearance"] == "NOT_CLEAR"


def test_catalog_dispatch_and_end_to_end_cli_generation_and_replay(
    tmp_path, capsys
) -> None:
    assert main(["gates", "--catalog", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["gates"]
    root = tmp_path / "source"
    report, contract, pin = fixture(root)
    report_path, contract_path, clearance_path = (
        tmp_path / name for name in ("report.json", "contract.json", "clearance.json")
    )
    report_path.write_bytes(workflow.canonical(report))
    contract_path.write_bytes(contract)
    shared = [
        str(root),
        "--preparation-contract",
        str(contract_path),
        "--preparation-contract-digest",
        pin,
        "--json",
    ]
    assert (
        main(
            [
                "gates",
                *shared,
                "--polish-report",
                str(report_path),
                "--output",
                str(clearance_path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["coverage"]["preparation_status"] == "PASS"
    assert main(["gates", *shared, "--check", str(clearance_path)]) == 0
    assert json.loads(capsys.readouterr().out)["clearance_id"] == result["clearance_id"]


def test_existing_source_admission_is_not_waived_by_workflow_selection(
    tmp_path,
) -> None:
    root = tmp_path / "source"
    report, contract, pin = fixture(root)
    (root / "demo.py").write_bytes(b"not valid python !!\n")
    value = json.loads(contract)
    policy = json.loads(value["policy_json"])
    for stage in policy["stages"]:
        if stage["id"] == "quality":
            stage.update(selected=False, required=False)
    policy_raw = workflow.canonical(policy)
    value["policy_json"], value["policy_digest"] = policy_raw.decode(), workflow.digest(
        policy_raw
    )
    # The independently replayed older admission checker still rejects invalid Python.
    report = workflow.prepare_workflow(
        root,
        policy_bytes=policy_raw,
        expected_policy_digest=workflow.digest(policy_raw),
        quality_profile_bytes=value["quality_profile_json"].encode(),
        expected_quality_profile_digest=value["quality_profile_digest"],
    )
    assert report["status"] == "PASS"
    contract = workflow.canonical(value)
    rejected = run(root, report, contract, workflow.digest(contract))
    assert (
        rejected["coverage"]["preparation_status"] == "FAIL"
        and rejected["clearance"] == "NOT_CLEAR"
    )
