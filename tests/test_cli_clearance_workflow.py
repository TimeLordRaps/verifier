"""Terminology: command-line interface (CLI).
Clearance must replay exact bytes and external intent.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
These are local observations; no network or production publication is exercised.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import object_facets
from verifier.runtime.artifact_snapshot import capture, digest
from verifier.runtime.clearance_publish import prepare_clearance_publication
from verifier.runtime.gates import DEFAULT_POLICY, run_gates, shipped_registry, validate_clearance
from verifier.runtime.polish_prepare import prepare_artifact
from verifier.runtime.public_cli import main


def source(tmp_path: Path) -> Path:
    target = tmp_path / "program.py"
    target.write_bytes(b"result = 2 + 3\n")
    return target


def prepared(target: Path) -> bytes:
    return canonical_bytes(prepare_artifact(target))


def gate_rows(result: dict) -> dict:
    return {row["gate_id"]: row for row in result["gates"]}


def test_registered_shipped_routes_are_discovered_deterministically() -> None:
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    registry = shipped_registry()
    ids = [row["id"] for row in registry]
    assert ids == sorted(set(ids))
    assert {"ast", "paths", "boundary", "pr", "attest", "pipeline-check", "polish-assess", "domain-check"} <= set(ids)
    assert len(registry) == 9 + len(current_object_route_catalog())


def test_polish_gates_cli_requires_separate_dependency_clearance_for_publication(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = source(tmp_path)
    preparation, clearance, envelope = [tmp_path / name for name in ("preparation.json", "clearance.json", "envelope.json")]
    assert main(["polish", str(target), "--dry-run", "--output", str(preparation), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["polished"] is False
    assert main(["gates", str(target), "--polish-report", str(preparation), "--output", str(clearance), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["clearance"] == "CLEAR"
    assert {gate_rows(result)[name]["status"] for name in ("paths", "ast", "boundary")} == {"PASS"}
    assert main(["gates", str(target), "--check", str(clearance), "--json"]) == 0
    capsys.readouterr()
    assert main(["publish", "--clearance", str(clearance), "--artifact", str(target), "--dry-run", "--output", str(envelope), "--json"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["result"] == "REJECTED" and summary["transport_performed"] is False
    assert not envelope.exists()



def test_prepare_dry_run_diff_apply_and_old_clearance_rejection(tmp_path: Path) -> None:
    target = source(tmp_path)
    initial = target.read_bytes()
    report = run_gates(target, polish_report_bytes=prepared(target))
    target.write_bytes(b"result = 2 + 3\r\n")
    dry = prepare_artifact(target, normalize_text=True)
    assert dry["status"] == "UNKNOWN" and dry["changes"]
    assert target.read_bytes().endswith(b"\r\n")
    applied = prepare_artifact(target, normalize_text=True, apply=True)
    assert applied["status"] == "PASS" and applied["mode"] == "APPLY"
    assert target.read_bytes() == initial
    # Same exact final artifact can reuse the original result. A changed final artifact cannot.
    assert validate_clearance(canonical_bytes(report), target)["clearance"] == "CLEAR"
    target.write_bytes(b"result = 6\n")
    with pytest.raises(ValueError):
        validate_clearance(canonical_bytes(report), target)


def test_post_apply_preparation_is_accepted(tmp_path: Path) -> None:
    target = source(tmp_path)
    target.write_bytes(b"result = 3\r\n")
    report = prepare_artifact(target, normalize_text=True, apply=True)
    assert run_gates(target, polish_report_bytes=canonical_bytes(report))["status"] == "PASS"


def test_secret_and_evidence_bytes_are_never_normalized(tmp_path: Path) -> None:
    target = tmp_path / "evidence.json"
    raw = b'{"schema_version":"unknown","value":1}\r\n'
    target.write_bytes(raw)
    assert prepare_artifact(target, normalize_text=True, apply=True)["changes"] == []
    assert target.read_bytes() == raw
    secret = tmp_path / "secret.py"
    material = ("token = '" + "sk-" + "A" * 40 + "'\r\n").encode()
    secret.write_bytes(material)
    report = prepare_artifact(secret, normalize_text=True)
    assert report["status"] == "FAIL" and report["changes"] == []
    assert material.decode().strip() not in json.dumps(report)
    with pytest.raises(ValueError):
        prepare_artifact(secret, normalize_text=True, apply=True)
    assert secret.read_bytes() == material


def test_gates_no_preparation_is_unknown(tmp_path: Path) -> None:
    result = run_gates(source(tmp_path), polish_report_bytes=None)
    assert result["status"] == "UNKNOWN" and result["clearance"] == "NOT_CLEAR"
    assert gate_rows(result)["ast"]["status"] == "PASS"


@pytest.mark.parametrize("payload", [b"\x00\xff", b'{"schema_version":"made-up","status":"PASS","argv":["danger"]}'])
def test_unsupported_artifacts_do_not_clear(tmp_path: Path, payload: bytes) -> None:
    target = tmp_path / ("artifact.json" if payload.startswith(b"{") else "artifact.bin")
    target.write_bytes(payload)
    report = run_gates(target, polish_report_bytes=prepared(target))
    assert report["status"] == "UNKNOWN" and report["clearance"] == "NOT_CLEAR"
    assert gate_rows(report)["artifact-contract"]["status"] == "UNSUPPORTED"


def test_metadata_cannot_execute_arbitrary_program(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("metadata execution attempted")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    target = tmp_path / "metadata.json"
    target.write_text('{"schema_version":"verifier-gate-pipeline-1","steps":[{"argv":["danger"]}]}', encoding="utf-8")
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "UNKNOWN"


def test_missing_checker_and_required_evidence_never_skip_to_pass(tmp_path: Path) -> None:
    target = source(tmp_path)
    policy = deepcopy(DEFAULT_POLICY)
    policy["required_gates"] = ["domain-check", "unregistered-checker"]
    result = run_gates(target, polish_report_bytes=prepared(target), policy_bytes=canonical_bytes(policy))
    assert result["status"] == "UNKNOWN"
    assert gate_rows(result)["domain-check"]["status"] == "UNKNOWN"
    assert gate_rows(result)["unregistered-checker"]["status"] == "UNSUPPORTED"


def test_missing_dependency_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import gate
    def unavailable(*args: object, **kwargs: object) -> None:
        raise ImportError("checker unavailable")
    monkeypatch.setattr(gate, "run_ast_gate", unavailable)
    target = source(tmp_path)
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "UNKNOWN"
    assert gate_rows(result)["ast"]["reason"] == "CHECKER_OR_DEPENDENCY_UNAVAILABLE"


def test_mutation_during_checks_fails_exact_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import gate
    target = source(tmp_path)
    original = gate.run_ast_gate
    def mutate(*args: object, **kwargs: object) -> tuple:
        target.write_bytes(b"result = 8\n")
        return original(*args, **kwargs)
    monkeypatch.setattr(gate, "run_ast_gate", mutate)
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "FAIL" and result["inputs_unchanged"] is False


@pytest.mark.parametrize("field", ["status", "gate", "coverage", "registry", "implementation"])
def test_rehashed_forged_clearance_is_rejected(tmp_path: Path, field: str) -> None:
    target = source(tmp_path)
    result = run_gates(target, polish_report_bytes=prepared(target))
    if field == "status":
        result["clearance"] = "NOT_CLEAR"
    elif field == "gate":
        result["gates"].pop()
    elif field == "coverage":
        result["coverage"]["passed"] += 1
    elif field == "registry":
        result["registry"][0]["version"] = "changed"
    else:
        result["implementation_digest"] = "sha256:" + "0" * 64
    result["clearance_id"] = digest(canonical_bytes({k: v for k, v in result.items() if k != "clearance_id"}))
    with pytest.raises(ValueError):
        validate_clearance(canonical_bytes(result), target)


def test_external_policy_change_rejects_clearance(tmp_path: Path) -> None:
    target = source(tmp_path)
    result = run_gates(target, polish_report_bytes=prepared(target))
    policy = deepcopy(DEFAULT_POLICY)
    policy["forbidden_terms"] = ["result"]
    with pytest.raises(ValueError, match="externally expected"):
        validate_clearance(canonical_bytes(result), target, expected_policy_bytes=canonical_bytes(policy))
    changed = run_gates(target, polish_report_bytes=prepared(target), policy_bytes=canonical_bytes(policy))
    assert changed["status"] == "FAIL" and gate_rows(changed)["boundary"]["status"] == "FAIL"


def test_native_current_object_replay_requires_external_request(tmp_path: Path) -> None:
    item = NamespaceObject.create("root", "OBJECT", {"value": 3})
    policy = object_facets.object_facets_policy(trust_roots=("external-test-selector",))
    request = object_facets.object_facets_request(item, policy=policy)
    certificate = object_facets.build_object_facets_certificate(request, canonical_bytes(item.to_dict()), policy=policy)
    target = tmp_path / "certificate.json"
    target.write_bytes(certificate)
    identity = "current-object:" + object_facets.SEMANTIC_VERSION + ":OBJECT-1.1"
    missing = run_gates(target, polish_report_bytes=prepared(target))
    assert gate_rows(missing)[identity]["status"] == "UNKNOWN"
    selected = deepcopy(DEFAULT_POLICY)
    selected["selections"] = [{"gate_id": identity, "path": "artifact.json", "request": request,
                               "policy": policy, "represented_kind": "OBJECT", "contract_version": "1"}]
    result = run_gates(target, polish_report_bytes=prepared(target), policy_bytes=canonical_bytes(selected))
    assert gate_rows(result)[identity]["status"] == "PASS" and result["status"] == "PASS"
    selected["selections"][0]["request"]["object_id"] = "wrong"
    rejected = run_gates(target, polish_report_bytes=prepared(target), policy_bytes=canonical_bytes(selected))
    assert rejected["status"] == "FAIL"


def test_unsigned_attestation_never_proves_execution(tmp_path: Path) -> None:
    from verifier.runtime.gate import create_ci_attestation_receipt
    receipt = create_ci_attestation_receipt(workflow="test", run_id="1", job="test", actor="test", commit_sha="0"*40)
    target = tmp_path / "attestation.json"
    target.write_bytes(canonical_bytes(receipt))
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "UNKNOWN" and gate_rows(result)["attest"]["status"] == "UNKNOWN"


def test_clearance_publish_blocks_live_mode_and_rejects_stale_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = source(tmp_path)
    clearance = tmp_path / "clearance.json"
    clearance.write_bytes(canonical_bytes(run_gates(target, polish_report_bytes=prepared(target))))
    assert main(["publish", "--clearance", str(clearance), "--artifact", str(target), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["transport_performed"] is False
    target.write_bytes(b"result = 9\n")
    with pytest.raises(ValueError):
        prepare_clearance_publication(target, clearance.read_bytes())


def test_output_cannot_mutate_selected_scope_and_no_overwrite(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = source(tmp_path)
    before = target.read_bytes()
    assert main(["polish", str(target), "--output", str(target), "--json"]) == 1
    capsys.readouterr()
    assert target.read_bytes() == before
    report = tmp_path / "report.json"
    report.write_bytes(b"keep")
    assert main(["polish", str(target), "--output", str(report), "--json"]) == 1
    assert report.read_bytes() == b"keep"


def test_directory_additions_change_artifact_identity(tmp_path: Path) -> None:
    directory = tmp_path / "artifact"
    directory.mkdir()
    source(directory)
    result = run_gates(directory, polish_report_bytes=prepared(directory))
    assert result["status"] == "PASS"
    (directory / "extra.py").write_bytes(b"extra = 1\n")
    with pytest.raises(ValueError):
        validate_clearance(canonical_bytes(result), directory)


def test_snapshot_bound_and_no_implicit_exclusions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import artifact_snapshot
    directory = tmp_path / "artifact"
    directory.mkdir()
    source(directory)
    ignored_by_old_scanner = directory / "build"
    ignored_by_old_scanner.mkdir()
    (ignored_by_old_scanner / "bad.py").write_bytes(b"while True:\n    pass\n")
    result = run_gates(directory, polish_report_bytes=prepared(directory))
    assert result["status"] == "FAIL" and gate_rows(result)["ast"]["status"] == "FAIL"
    monkeypatch.setattr(artifact_snapshot, "MAX_FILES", 1)
    with pytest.raises(ValueError):
        capture(directory)


def test_tampered_attestation_remains_failure(tmp_path: Path) -> None:
    from verifier.runtime.gate import create_ci_attestation_receipt
    receipt = create_ci_attestation_receipt(workflow="test", run_id="1", job="test", actor="test", commit_sha="0"*40)
    receipt["attestation"]["job"] = "changed"
    target = tmp_path / "attestation.json"
    target.write_bytes(canonical_bytes(receipt))
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "FAIL" and gate_rows(result)["attest"]["status"] == "FAIL"


def test_self_declared_unknown_coordinate_cannot_suppress_replay(tmp_path: Path) -> None:
    target = tmp_path / "certificate.json"
    target.write_bytes(canonical_bytes({"schema_version": object_facets.CERTIFICATE_VERSION,
        "request": {"coordinate": "FORGED-9.1", "semantic_version": object_facets.SEMANTIC_VERSION},
        "result": {"status": "PASS"}}))
    result = run_gates(target, polish_report_bytes=prepared(target))
    assert result["status"] == "UNKNOWN" and result["clearance"] == "NOT_CLEAR"
    assert gate_rows(result)["artifact-contract"]["status"] == "UNSUPPORTED"


@pytest.mark.parametrize("value,field,status", [(3,"integer","PASS"),("wrong","integer","FAIL"),(3,"unsupported-type","UNKNOWN")])
def test_native_data_artifact_preserves_all_verdicts(tmp_path: Path, value: object, field: str, status: str) -> None:
    from test_current_data_checks import commitment, inputs
    artifact = {"shards": {"records": commitment([{"value": value}])}, "fields": {"value": field}}
    contract, request, policy, evidence = inputs("schema", artifact=artifact, retained={"shards": {"records": [{"value": value}]}})
    certificate = contract.build_data_checks_certificate(request, evidence, policy=policy)
    directory = tmp_path / "native"
    directory.mkdir()
    (directory / "certificate.json").write_bytes(certificate)
    gates_policy = deepcopy(DEFAULT_POLICY)
    identifier = "current-object:" + contract.SEMANTIC_VERSION + ":DATA-1.4"
    gates_policy["selections"] = [{"gate_id": identifier, "path": "certificate.json",
        "request": request, "policy": policy, "represented_kind": "DATA", "contract_version": "1"}]
    result = run_gates(directory, polish_report_bytes=prepared(directory), policy_bytes=canonical_bytes(gates_policy))
    assert gate_rows(result)[identifier]["status"] == status
    assert result["status"] == status
    assert result["clearance"] == ("CLEAR" if status == "PASS" else "NOT_CLEAR")
    if status == "PASS":
        with pytest.raises(ValueError, match="dependency"):
            prepare_clearance_publication(directory, canonical_bytes(result), expected_policy_bytes=canonical_bytes(gates_policy))


def test_current_polish_bundle_cannot_fabricate_complete_issuance(tmp_path: Path) -> None:
    from verifier.core.namespace import composition_digest
    item = NamespaceObject.create("root", "OBJECT", {"value": 3})
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [item.to_dict()], "certificates": {}}
    raw = canonical_bytes(bundle)
    request = {"schema_version": "verifier-polish-request-1", "root_id": "root", "collection_digest": composition_digest([item]),
        "bundle_digest": digest(raw), "requirements": []}
    target = tmp_path / "bundle.json"
    target.write_bytes(raw)
    policy = deepcopy(DEFAULT_POLICY)
    policy["selections"] = [{"gate_id": "polish-assess", "path": "artifact.json", "request": request,
        "policy": {}, "represented_kind": None, "contract_version": "1"}]
    report = run_gates(target, polish_report_bytes=prepared(target), policy_bytes=canonical_bytes(policy))
    assert report["status"] == "UNKNOWN" and report["clearance"] == "NOT_CLEAR"
    assert gate_rows(report)["polish-assess"]["status"] == "UNKNOWN"
