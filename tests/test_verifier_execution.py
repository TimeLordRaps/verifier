"""Real-process resource falsifiers for Verifier Standard (VSTD) native replay.

Windows-only process tests declare the operating system (OS) capability boundary.
The admitted command never comes from evidence; private runner probes use only
test-authored Python programs and fresh owned processes.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys

import pytest

from test_verifier_grounding import native_bundle, public_result
from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.verifier import evaluate


WINDOWS = pytest.mark.skipif(os.name != "nt", reason="OS_CAPABILITY_GUARD: Windows Job Object execution requires Windows")


def resource_bundle() -> tuple[dict, dict]:
    artifact, inputs = native_bundle()
    artifact["ceilings"] = {"max_memory_bytes": 128 * 1024 * 1024,
                            "max_wall_seconds": 10.0, "max_loop_iterations": 50000}
    inputs["resource_execution"] = {"mechanism": "windows-job-native-kernel-1"}
    return artifact, inputs


@WINDOWS
def test_public_resource_opt_in_executes_native_proof_under_limits() -> None:
    artifact, inputs = resource_bundle()
    result = evaluate("resources", artifact, inputs, Budget(100000))
    assert result["mechanism"] == "windows-job-native-kernel-1"
    assert result["proof_instances_checked"] == 1
    assert result["proof_output_digest"] == inputs["runs"][0]["output_digest"]
    assert result["applied_limits"]["job_committed_memory_bytes"] == artifact["ceilings"]["max_memory_bytes"]
    assert result["limits_verified_before_resume"] is True
    assert result["owned_job_empty"] is True
    assert result["arbitrary_verifier_execution"] == "NOT_ESTABLISHED"
    assert result == evaluate("resources", artifact, inputs, Budget(100000))


@WINDOWS
def test_resource_certification_reaches_depth_four_and_rechecks() -> None:
    artifact, inputs = resource_bundle()
    result = public_result(artifact, inputs, depth=4)
    assert result["status"] == "PASS"
    assert result["domain_depth"] == 4
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    observed = result["checks"]["VERIFIER-1.4"]["evaluation"]["observations"]
    assert observed["proof_output_digest"] == inputs["runs"][0]["output_digest"]


@WINDOWS
@pytest.mark.parametrize("refutation", [False, True])
def test_complete_native_verifier_certificate_reaches_five_checks_and_rechecks(refutation: bool) -> None:
    pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: bootstrap signatures require the seal extra")
    from test_verifier_bootstrap import signed_bundle
    artifact, inputs, keys = signed_bundle(refutation=refutation)
    artifact["ceilings"] = {"max_memory_bytes": 128 * 1024 * 1024,
                            "max_wall_seconds": 5.0, "max_loop_iterations": 50000}
    inputs["resource_execution"] = {"mechanism": "windows-job-native-kernel-1"}
    result = public_result(artifact, inputs, depth=5, witness_keys=keys)
    assert result["status"] == "PASS"
    assert result["domain_depth"] == 5
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert all(check["established"] for check in result["checks"].values())
    assert result["checks"]["VERIFIER-1.5"]["evaluation"]["observations"]["general_verifier_soundness"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", ["evidence", "certification"])
def test_resource_selection_schema_accepts_exact_opt_in_and_rejects_other_commands(kind: str) -> None:
    from jsonschema import Draft202012Validator
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
    artifact, inputs = resource_bundle()
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "VERIFIER",
                "subject_id": artifact["verifier_id"], "artifact": artifact, "inputs": inputs}
    policy = domain_policy(trust_roots=["test:native-resource-schema"])
    value = evidence if kind == "evidence" else build_domain_certificate(
        domain_request(evidence, target_depth=3), evidence, policy=policy)
    schema = Path(__file__).resolve().parents[1] / "src/verifier/schemas" / ("verifier-domain-" + kind + "-1.schema.json")
    validator = Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))
    validator.validate(value)
    for invalid in (None, {}, {"mechanism": "arbitrary-code"},
                    {"mechanism": "windows-job-native-kernel-1", "argv": ["untrusted-command"]}):
        changed = deepcopy(value)
        target = changed if kind == "evidence" else changed["evidence"]
        target["inputs"]["resource_execution"] = invalid
        assert list(validator.iter_errors(changed)), invalid


@WINDOWS
@pytest.mark.parametrize("mutation", ["proof", "input", "toolchain"])
def test_executed_native_proof_rejects_substitution(mutation: str) -> None:
    artifact, inputs = resource_bundle()
    if mutation == "proof":
        inputs["soundness_claims"][0]["refutation_witness"]["certificate"]["decision"]["model"]["1"] = False
        artifact["soundness_claims_digest"] = digest(inputs["soundness_claims"])
    elif mutation == "input":
        artifact["soundness_claims_digest"] = "sha256:" + "0" * 64
    else:
        artifact["toolchain_digest"] = "sha256:" + "0" * 64
    from verifier.domains.verifier_execution import evaluate_resources
    with pytest.raises(Refuted):
        evaluate_resources(artifact, inputs, Budget(100000))


@WINDOWS
def test_child_work_budget_exhaustion_cannot_pass() -> None:
    from verifier.domains.verifier_execution import evaluate_resources
    artifact, inputs = resource_bundle()
    artifact["ceilings"]["max_loop_iterations"] = 1
    with pytest.raises(Unavailable, match="work|operation"):
        evaluate_resources(artifact, inputs, Budget(100000))


def test_parent_budget_bounds_child_work_before_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains import verifier_execution as execution
    artifact, inputs = resource_bundle()
    monkeypatch.setattr(execution, "_supported_platform", lambda: True)
    def forbidden(*args: object, **kwargs: object) -> dict:
        pytest.fail("parent budget exhaustion must prevent a child process")
    monkeypatch.setattr(execution, "_run_windows", forbidden)
    with pytest.raises(Unavailable, match="operation"):
        execution.evaluate_resources(artifact, inputs, Budget(100))


def test_submitted_command_is_never_an_admitted_resource_input() -> None:
    from verifier.domains.verifier_execution import evaluate_resources
    artifact, inputs = resource_bundle()
    inputs["resource_execution"]["argv"] = [sys.executable, "-c", "raise SystemExit(0)"]
    with pytest.raises(Refuted):
        evaluate_resources(artifact, inputs, Budget(100000))


def test_unsupported_platform_does_not_manufacture_resource_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains import verifier_execution as execution
    artifact, inputs = resource_bundle()
    monkeypatch.setattr(execution, "_supported_platform", lambda: False)
    with pytest.raises(Unavailable, match="Windows"):
        execution.evaluate_resources(artifact, inputs, Budget(100000))


@WINDOWS
def test_real_job_denies_allocation_above_committed_memory_cap() -> None:
    from verifier.domains.verifier_execution import _run_windows
    program = "try:\n x=bytearray(128*1024*1024)\n print('UNBOUNDED')\nexcept MemoryError:\n print('MEMORY_DENIED')"
    result = _run_windows([sys.executable, "-I", "-S", "-B", "-u", "-c", program],
                          b"", 64 * 1024 * 1024, 5.0)
    assert result["stdout"].strip() == b"MEMORY_DENIED"
    assert result["exit_code"] == 0
    assert result["owned_job_empty"] is True
    assert result["applied_limits"]["job_committed_memory_bytes"] == 64 * 1024 * 1024
    assert result["limits_verified_before_resume"] is True


@WINDOWS
def test_real_wall_watchdog_terminates_owned_descendant() -> None:
    import _winapi
    from verifier.domains.verifier_execution import _run_windows
    program = ("import subprocess,sys,time; "
               "p=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)']); "
               "print(p.pid,flush=True); time.sleep(30)")
    result = _run_windows([sys.executable, "-I", "-S", "-B", "-u", "-c", program],
                          b"", 128 * 1024 * 1024, 1.0)
    assert result["timed_out"] is True
    assert result["owned_job_empty"] is True
    child = int(result["stdout"].strip())
    try:
        handle = _winapi.OpenProcess(0x00100000, False, child)
    except OSError:
        return
    try:
        assert _winapi.WaitForSingleObject(handle, 0) == 0
    finally:
        _winapi.CloseHandle(handle)


@WINDOWS
def test_limit_query_failure_never_resumes_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains import verifier_execution as execution
    marker = tmp_path / "unexpected-execution"
    program = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('executed')"
    resumed: list[bool] = []
    original_resume = execution._WindowsJob.resume
    def observed_resume(self: object, handle: int) -> None:
        resumed.append(True)
        original_resume(self, handle)
    def failed_query(self: object) -> dict:
        assert not resumed
        raise OSError("independent limit query unavailable")
    monkeypatch.setattr(execution._WindowsJob, "verify_limits", failed_query)
    monkeypatch.setattr(execution._WindowsJob, "resume", observed_resume)
    with pytest.raises(OSError, match="limit query"):
        execution._run_windows([sys.executable, "-I", "-S", "-B", "-u", "-c", program, str(marker)],
                               b"", 128 * 1024 * 1024, 5.0)
    assert not marker.exists()


@WINDOWS
def test_child_native_work_cannot_exceed_reported_budget_charge() -> None:
    from verifier.domains.verifier_execution import evaluate_resources
    artifact, inputs = resource_bundle()
    passed = evaluate_resources(artifact, inputs, Budget(100000))
    artifact["ceilings"]["max_loop_iterations"] = passed["native_work_used"] - 1
    with pytest.raises(Unavailable, match="native work"):
        evaluate_resources(artifact, inputs, Budget(100000))


@WINDOWS
def test_overcap_job_accounting_prevents_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes
    from verifier.domains.verifier_execution import _WindowsJob
    cap = 64 * 1024 * 1024
    job = _WindowsJob(cap)
    original_query = job.kernel.QueryInformationJobObject
    def overcap_query(handle: object, kind: int, buffer: object, size: int, returned: object) -> int:
        result = original_query(handle, kind, buffer, size, returned)
        if result and kind == 9:
            # Model an OS-reported historical peak, not a caller declaration.
            ctypes.cast(buffer, ctypes.POINTER(job.extended_type)).contents.peak_job = cap + 1
        return result
    monkeypatch.setattr(job.kernel, "QueryInformationJobObject", overcap_query)
    try:
        with pytest.raises(OSError, match="memory peak"):
            job.verify_limits()
    finally:
        job.close()
