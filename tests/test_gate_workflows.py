"""Verifier Standard (VSTD) command-line interface (CLI) workflow acceptance tests.

JavaScript Object Notation (JSON); DATA means dataset integrity and lineage.
Command outcomes are distinct from independently replayed domain correctness.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from verifier.runtime.gate_pipeline import check_pipeline, init_pipeline, plan_pipeline, run_pipeline


def pipeline(root: Path, outcome: str = "UNKNOWN", code: int = 2,
             *, contract: bool = True, payload: str | None = None) -> Path:
    (root / "input.txt").write_text("bound project input", encoding="utf-8")
    output = json.dumps({"status": outcome}) if payload is None else payload
    step = {"id": "assess", "argv": [sys.executable, "-B", "-c",
            f"print({output!r}); raise SystemExit({code})"], "needs": [], "timeout_seconds": 3}
    if contract:
        step["result_contract"] = "vstd-verdict"
    value = {"schema_version": "verifier-gate-pipeline-1", "root": ".", "inputs": ["input.txt"],
             "steps": [step], "overall_timeout_seconds": 10, "max_output_bytes": 16384}
    path = root / "pipeline.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.mark.parametrize("outcome,code", [("PASS", 0), ("FAIL", 1), ("UNKNOWN", 2)])
def test_explicit_verdict_round_trip_preserves_status_and_exit(tmp_path: Path, outcome: str, code: int) -> None:
    manifest = pipeline(tmp_path, outcome, code)
    receipt = tmp_path / "receipt.json"
    result = run_pipeline(manifest, receipt)
    assert result["status"] == result["steps"][0]["status"] == outcome
    assert check_pipeline(receipt)["run_status"] == outcome
    completed = subprocess.run([sys.executable, "-B", "-m", "verifier", "gate", "check", str(receipt), "--json"],
                               capture_output=True, text=True, timeout=10, check=False)
    assert completed.returncode == code
    assert json.loads(completed.stdout)["status"] == outcome
    executed = subprocess.run([sys.executable, "-B", "-m", "verifier", "gate", "run", str(manifest),
                               "--output", str(tmp_path / "cli-receipt.json"), "--json"],
                              capture_output=True, text=True, timeout=10, check=False)
    assert executed.returncode == code
    assert json.loads(executed.stdout)["status"] == outcome


def test_generic_exit_two_is_still_failure(tmp_path: Path) -> None:
    manifest = pipeline(tmp_path, contract=False)
    result = run_pipeline(manifest, tmp_path / "receipt.json")
    assert result["status"] == result["steps"][0]["status"] == "FAIL"


@pytest.mark.parametrize("payload,code", [("not JSON", 0), ('{"status":"PASS"}', 2),
    ('{"status":"UNKNOWN"}', 0), ('{"status":"PASS","status":"UNKNOWN"}', 2), ('{}', 0),
    ('{"status":"PASS","value":NaN}', 0)])
def test_verdict_contract_rejects_malformed_or_contradictory_output(tmp_path: Path, payload: str, code: int) -> None:
    manifest = pipeline(tmp_path, code=code, payload=payload)
    result = run_pipeline(manifest, tmp_path / "receipt.json")
    assert result["status"] == "FAIL"
    assert result["steps"][0]["status"] == "ERROR"


def test_unknown_blocks_dependents_but_independent_failure_dominates(tmp_path: Path) -> None:
    manifest = pipeline(tmp_path)
    value = json.loads(manifest.read_text())
    value["steps"].append({"id": "dependent", "argv": [sys.executable, "-B", "-c", "raise RuntimeError('blocked')"],
                           "needs": ["assess"], "timeout_seconds": 2})
    manifest.write_text(json.dumps(value))
    result = run_pipeline(manifest, tmp_path / "unknown.json")
    assert result["status"] == "UNKNOWN"
    assert [step["status"] for step in result["steps"]] == ["UNKNOWN", "BLOCKED"]
    value["steps"].append({"id": "independent", "argv": [sys.executable, "-B", "-c", "raise SystemExit(7)"],
                           "needs": [], "timeout_seconds": 2})
    manifest.write_text(json.dumps(value))
    result = run_pipeline(manifest, tmp_path / "failed.json")
    assert result["status"] == "FAIL"


def test_progress_streams_child_output_before_process_exit(tmp_path: Path) -> None:
    manifest = pipeline(tmp_path, contract=False)
    value = json.loads(manifest.read_text())
    value["steps"][0]["argv"] = [sys.executable, "-B", "-u", "-c",
        "import time; print('named-test-started',flush=True); time.sleep(.7); print('named-test-finished',flush=True)"]
    manifest.write_text(json.dumps(value))
    events = []
    started = time.monotonic()
    run_pipeline(manifest, tmp_path / "receipt.json", progress=lambda text: events.append((time.monotonic()-started, text)))
    first = [stamp for stamp, text in events if "named-test-started" in text]
    finished = [stamp for stamp, text in events if "named-test-finished" in text]
    assert first and finished
    assert finished[0] - first[0] >= .4


def test_project_preset_checks_actual_sources_and_detects_leak(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    sample = source / "sample.py"
    sample.write_text("value = 1\n", encoding="utf-8")
    manifest = tmp_path / "pipeline.json"
    init_pipeline(manifest, inputs=["src"])
    assert plan_pipeline(manifest)["status"] == "PASS"
    assert run_pipeline(manifest, tmp_path / "clean.json")["status"] == "PASS"
    sample.write_text("location = " + repr("/" + "home/person/private") + "\n", encoding="utf-8")
    result = run_pipeline(manifest, tmp_path / "leak.json")
    assert result["status"] == "FAIL"
    assert any(step["status"] == "FAIL" for step in result["steps"])


def test_rehashed_unknown_cannot_be_promoted_to_pass(tmp_path: Path) -> None:
    from verifier.runtime.gate_pipeline import _canonical, _digest
    manifest = pipeline(tmp_path)
    receipt = tmp_path / "receipt.json"
    value = run_pipeline(manifest, receipt)
    value["steps"][0]["status"] = value["status"] = "PASS"
    value["steps"][0]["exit_code"] = 0
    value.pop("receipt_digest")
    value["receipt_digest"] = _digest(_canonical(value))
    receipt.write_text(json.dumps(value))
    assert check_pipeline(receipt)["status"] == "FAIL"


@pytest.mark.parametrize("expected,field_type,value", [("PASS", "integer", 3), ("FAIL", "integer", "wrong"),
                                                     ("UNKNOWN", "unsupported-type", 3)])
def test_native_domain_assess_and_check_verdict_contract(tmp_path: Path, expected: str, field_type: str, value: object) -> None:
    from verifier.core.certificate import canonical_bytes
    from verifier.domains.certification import domain_policy, domain_request
    from verifier.domains.common import Budget, digest, merkle_root
    rows = [{"value": value}]
    commitment = {"digest": digest(rows), "records": 1, "bytes": len(canonical_bytes(rows)),
                  "record_digests": [digest(row) for row in rows], "merkle_root": merkle_root(rows, Budget(10000))}
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "DATA", "subject_id": "test:selected-data",
                "artifact": {"shards": {"data": commitment}, "fields": {"value": field_type}}, "inputs": {"shards": {"data": rows}}}
    request = domain_request(evidence, target_depth=2)
    policy = domain_policy(trust_roots=["test:consumer-selected-checker"])
    for name, document in (("request", request), ("policy", policy), ("evidence", evidence)):
        (tmp_path / (name + ".json")).write_text(json.dumps(document), encoding="utf-8")
    manifest = pipeline(tmp_path)
    plan = json.loads(manifest.read_text())
    plan["inputs"] = ["request.json", "policy.json", "evidence.json"]
    plan["max_output_bytes"] = 65536
    plan["steps"][0]["argv"] = [sys.executable, "-B", "-m", "verifier", "certification", "domain-assess", "evidence.json",
                               "--request", "request.json", "--policy", "policy.json", "--output", "certificate.json", "--json"]
    manifest.write_text(json.dumps(plan))
    assessed = run_pipeline(manifest, tmp_path / "assess-receipt.json")
    assert assessed["status"] == assessed["steps"][0]["status"] == expected
    assert json.loads(assessed["steps"][0]["stdout"])["result"]["status"] == expected
    assert check_pipeline(tmp_path / "assess-receipt.json")["status"] == expected
    plan["inputs"].append("certificate.json")
    plan["steps"][0]["argv"] = [sys.executable, "-B", "-m", "verifier", "certification", "domain-check", "certificate.json",
                               "--request", "request.json", "--policy", "policy.json", "--json"]
    manifest.write_text(json.dumps(plan))
    checked = run_pipeline(manifest, tmp_path / "check-receipt.json")
    assert checked["status"] == checked["steps"][0]["status"] == expected
    assert json.loads(checked["steps"][0]["stdout"])["status"] == expected


@pytest.mark.parametrize("expected", ["PASS", "FAIL", "UNKNOWN"])
def test_real_example_executes_source_checks_and_dataset_contract(tmp_path: Path, expected: str) -> None:
    examples = Path(__file__).resolve().parents[1] / "examples"
    shutil.copyfile(examples / "gate_pipeline.json", tmp_path / "gate_pipeline.json")
    shutil.copytree(examples / "gate_project", tmp_path / "gate_project")
    if expected == "FAIL":
        dataset = tmp_path / "gate_project/dataset.json"
        rows = json.loads(dataset.read_text())
        rows[0]["value"] = "not an integer"
        dataset.write_text(json.dumps(rows))
    elif expected == "UNKNOWN":
        contract = tmp_path / "gate_project/contract.json"
        value = json.loads(contract.read_text())
        value["fields"]["value"] = "unsupported-type"
        contract.write_text(json.dumps(value))
    receipt = tmp_path / "receipt.json"
    result = run_pipeline(tmp_path / "gate_pipeline.json", receipt)
    assert result["status"] == expected
    assert [row["status"] for row in result["steps"]] == ["PASS", "PASS", "PASS", expected]
    assert check_pipeline(receipt)["status"] == expected


def test_python_preset_executes_source_pattern_gate(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "loop.py").write_text("while True:\n    pass\n", encoding="utf-8")
    manifest = tmp_path / "pipeline.json"
    init_pipeline(manifest, inputs=["src"], preset="python")
    result = run_pipeline(manifest, tmp_path / "receipt.json")
    assert result["status"] == "FAIL"
    assert next(row for row in result["steps"] if row["id"] == "ast_0")["status"] == "FAIL"
