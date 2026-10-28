"""Parent-side Verifier Standard (VSTD) execution observations, not child claims.

Transport-edge controls below do not execute a child. Separate package tests run
installed workers and check that these records reach the user-facing reports.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from test_package_polish import declared_package

from verifier.core.namespace import NamespaceObject
from verifier.runtime import package_execution as execution, local_ledger_execution as ledger
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


@pytest.fixture
def exchange(monkeypatch: pytest.MonkeyPatch) -> tuple:
    from verifier.runtime import local_ledger_worker
    item = NamespaceObject.create("observed", "OBJECT", {}, {})
    selected = {"object_id": item.object_id, "mechanism": ledger.ADAPTER,
        "reason": "Private transport observation control, not a production receipt.",
        "evidence": [{"path": ledger.IMPLEMENTATION, "sha256": "sha256:" + "a" * 64}]}
    snapshot = SimpleNamespace(rows={item.object_id: {"surfaces": ["file:" + ledger.IMPLEMENTATION]}},
        root=Path(__file__).resolve().parents[1],
        collection_digest="sha256:" + "b" * 64, read=lambda ref: b"",
        execution_transports={}, executions={}, execution_failures={},
        execution_checks={(item.object_id, ledger.ADAPTER): selected})
    monkeypatch.setattr(local_ledger_worker, "source_pins", lambda: {})
    return snapshot, item, selected


@pytest.mark.parametrize("fault", ["none", "exit", "malformed", "timeout", "launch", "capacity"])
def test_parent_records_actual_transport_even_when_reply_cannot_be_evidence(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    from verifier.core.receipt import strict_json_loads
    snapshot, item, selection = exchange
    sent, received = [], []

    def run(command: list[str], **kwargs: Any) -> Any:
        sent.append(kwargs["input"])
        if fault == "launch":
            raise OSError("Private launch failure")
        if fault == "timeout":
            raise subprocess.TimeoutExpired(command, 30, output=b"partial", stderr=b"diagnostic")
        report = {"schema_version": ledger.OBSERVATION_SCHEMA,
            "request": strict_json_loads(kwargs["input"].decode()), "source_pins": {}, "observations": {}}
        raw = b" {bad" if fault == "malformed" else canonical_bytes(report) + b"\n"
        if fault == "capacity":
            raw = b" " * (1048576 + 1)
        received.append(raw)
        return SimpleNamespace(returncode=1 if fault == "exit" else 0, stdout=raw, stderr=b"diagnostic")

    monkeypatch.setattr(execution.subprocess, "run", run)
    typed_reason = {"exit": "PACKAGE_EXECUTION_WORKER_UNAVAILABLE", "capacity": "PACKAGE_EXECUTION_OUTPUT_CAPACITY"}
    if fault == "none":
        execution.execute_bound(snapshot, item, selection)
    else:
        with pytest.raises((ValueError, OSError, subprocess.TimeoutExpired)) as raised:
            execution.execute_bound(snapshot, item, selection)
        if fault in typed_reason:
            assert str(raised.value) == typed_reason[fault]
    assert len(sent) == 1
    assert len(snapshot.execution_transports) == 1, "The parent must retain its own actual exchange."
    trace = snapshot.execution_transports[(item.object_id, ledger.ADAPTER)]
    assert trace["request"] == strict_json_loads(sent[0].decode())
    assert base64.b64decode(trace["stdin"]["retained_base64"]) == sent[0]
    assert trace["outcome"] == {"none": "ACCEPTED", "exit": "NONZERO_EXIT", "malformed": "REJECTED",
        "timeout": "TIMEOUT", "launch": "LAUNCH_ERROR", "capacity": "OUTPUT_CAP_EXCEEDED"}[fault]
    assert trace["observation_digest"] == value_digest({k: v for k, v in trace.items() if k != "observation_digest"})
    if received:
        assert base64.b64decode(trace["stdout"]["retained_base64"]) == received[0][:1048576]
        assert trace["stdout"]["truncated"] is (fault == "capacity")
    if fault == "capacity":
        # Output-cap transport is a typed capacity refusal, not a generic rejection, and its stream is incomplete.
        assert trace["streams_complete"] is False and trace["returncode"] is None
    if fault == "launch":
        assert trace["stdout"] is trace["stderr"] is None and trace["returncode"] is None
    if fault == "timeout":
        assert trace["streams_complete"] is False
        assert base64.b64decode(trace["stdout"]["retained_base64"]) == b"partial"
    assert trace["unobserved"] == ["child-filesystem", "child-network", "descendants", "external-effects"]


def test_child_temp_prefers_capacity_is_private_cleaned_and_parent_unchanged(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from verifier.core.receipt import strict_json_loads
    snapshot, item, selection = exchange
    lower, greater = tmp_path / "lower", tmp_path / "greater"
    lower.mkdir()
    greater.mkdir()
    monkeypatch.setattr(execution, "_temporary_parent_candidates", lambda root: (lower, greater))
    monkeypatch.setattr(execution.shutil, "disk_usage", lambda path: SimpleNamespace(
        free=10 if Path(path) == lower else 20))
    observed: dict[str, Path] = {}

    def run(command: list[str], **kwargs: Any) -> Any:
        directory = Path(kwargs["env"]["TEMP"])
        assert directory == Path(kwargs["env"]["TMP"]) == Path(kwargs["env"]["TMPDIR"])
        assert directory.parent == greater.resolve()
        assert directory.name.startswith("vstd-package-execution-")
        assert directory.is_dir()
        observed["directory"] = directory
        report = {"schema_version": ledger.OBSERVATION_SCHEMA,
            "request": strict_json_loads(kwargs["input"].decode()), "source_pins": {}, "observations": {}}
        return SimpleNamespace(returncode=0, stdout=canonical_bytes(report) + b"\n", stderr=b"")

    parent_environment = dict(os.environ)
    monkeypatch.setattr(execution.subprocess, "run", run)
    execution.execute_bound(snapshot, item, selection)
    assert not observed["directory"].exists()
    assert dict(os.environ) == parent_environment
    trace = snapshot.execution_transports[(item.object_id, ledger.ADAPTER)]
    assert set(trace["environment_keys"]) <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH"}
    assert str(observed["directory"]).encode() not in canonical_bytes(trace)


def test_child_temp_creation_failure_is_fail_closed_without_launch(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    snapshot, item, selection = exchange
    lower, greater = tmp_path / "lower", tmp_path / "greater"
    lower.mkdir()
    greater.mkdir()
    monkeypatch.setattr(execution, "_temporary_parent_candidates", lambda root: (lower, greater))
    monkeypatch.setattr(execution.shutil, "disk_usage", lambda path: SimpleNamespace(
        free=10 if Path(path) == lower else 20))
    attempted: list[Path] = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        attempted.append(Path(kwargs["dir"]))
        raise PermissionError("private temp refused")

    monkeypatch.setattr(execution.tempfile, "TemporaryDirectory", refuse)
    monkeypatch.setattr(execution.subprocess, "run",
        lambda *args, **kwargs: pytest.fail("worker must not launch without a private temp directory"))
    parent_environment = dict(os.environ)
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_PRIVATE_TEMP_UNAVAILABLE"):
        execution.execute_bound(snapshot, item, selection)
    assert attempted == [greater.resolve(), lower.resolve()]
    assert dict(os.environ) == parent_environment
    trace = snapshot.execution_transports[(item.object_id, ledger.ADAPTER)]
    assert trace["outcome"] == "LAUNCH_ERROR"
    assert trace["exception_type"] == "OSError"


@pytest.mark.parametrize("fault", ["launch", "timeout"])
def test_cleanup_failure_preserves_primary_error_without_retry(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fault: str) -> None:
    snapshot, item, selection = exchange
    directory = tmp_path / "private"
    directory.mkdir()
    monkeypatch.setattr(execution, "_temporary_parent_candidates", lambda root: (tmp_path,))
    monkeypatch.setattr(execution.shutil, "disk_usage", lambda path: SimpleNamespace(free=20))
    calls = {"create": 0, "cleanup": 0, "launch": 0}

    class RefusingCleanup:
        name = str(directory)

        def cleanup(self) -> None:
            calls["cleanup"] += 1
            raise OSError("cleanup refused")

    def temporary(*args: Any, **kwargs: Any) -> RefusingCleanup:
        calls["create"] += 1
        return RefusingCleanup()

    def run(command: list[str], **kwargs: Any) -> Any:
        calls["launch"] += 1
        if fault == "timeout":
            raise subprocess.TimeoutExpired(command, 30, output=b"partial", stderr=b"diagnostic")
        raise OSError("primary launch failure")

    monkeypatch.setattr(execution.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(execution.subprocess, "run", run)
    if fault == "timeout":
        with pytest.raises(subprocess.TimeoutExpired):
            execution.execute_bound(snapshot, item, selection)
    else:
        with pytest.raises(OSError, match="primary launch failure"):
            execution.execute_bound(snapshot, item, selection)
    assert calls == {"create": 1, "cleanup": 1, "launch": 1}
    trace = snapshot.execution_transports[(item.object_id, ledger.ADAPTER)]
    assert trace["outcome"] == ("TIMEOUT" if fault == "timeout" else "LAUNCH_ERROR")


def test_cleanup_failure_after_success_is_fail_closed_without_fallback(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from verifier.core.receipt import strict_json_loads
    snapshot, item, selection = exchange
    first, fallback = tmp_path / "first", tmp_path / "fallback"
    first.mkdir()
    fallback.mkdir()
    directory = first / "private"
    directory.mkdir()
    monkeypatch.setattr(execution, "_temporary_parent_candidates", lambda root: (first, fallback))
    monkeypatch.setattr(execution.shutil, "disk_usage", lambda path: SimpleNamespace(
        free=20 if Path(path) == first else 10))
    calls = {"create": 0, "cleanup": 0, "launch": 0}

    class RefusingCleanup:
        name = str(directory)

        def cleanup(self) -> None:
            calls["cleanup"] += 1
            raise OSError("cleanup refused")

    def temporary(*args: Any, **kwargs: Any) -> RefusingCleanup:
        calls["create"] += 1
        return RefusingCleanup()

    def run(command: list[str], **kwargs: Any) -> Any:
        calls["launch"] += 1
        report = {"schema_version": ledger.OBSERVATION_SCHEMA,
            "request": strict_json_loads(kwargs["input"].decode()), "source_pins": {}, "observations": {}}
        return SimpleNamespace(returncode=0, stdout=canonical_bytes(report) + b"\n", stderr=b"")

    monkeypatch.setattr(execution.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(execution.subprocess, "run", run)
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_PRIVATE_TEMP_CLEANUP_FAILED"):
        execution.execute_bound(snapshot, item, selection)
    assert calls == {"create": 1, "cleanup": 1, "launch": 1}
    trace = snapshot.execution_transports[(item.object_id, ledger.ADAPTER)]
    assert trace["outcome"] != "ACCEPTED"
    assert trace["exception_type"] == "OSError"


def test_temp_parent_candidates_require_checkout_and_exclude_source_tree(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(execution.tempfile, "gettempdir", lambda: str(source_root / "tests"))
    assert execution._temporary_parent_candidates(source_root) == (source_root.parent,)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    assert execution._temporary_parent_candidates(unrelated) == ()


@pytest.mark.parametrize("mechanism", list(execution.mechanisms()))
def test_missing_parent_observation_cannot_establish_execution(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, mechanism: str) -> None:
    snapshot, item, selection = exchange
    module = execution.mechanisms()[mechanism]
    selection["mechanism"] = mechanism
    snapshot.execution_checks = {(item.object_id, mechanism): selection}
    monkeypatch.setattr(module, "_execute", lambda *args: {"observations": {"claimed": "PASS"}})
    monkeypatch.setattr(module, "check_observations", lambda *args: True)
    result = execution.evaluate(snapshot, item, module.catalog()[0])
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "PACKAGE_EXECUTION_PARENT_OBSERVATION_UNAVAILABLE"


@pytest.mark.parametrize("fault", ["digest", "stdout", "stdin", "stderr", "selection", "pins", "worker", "flags",
    "environment", "environment-deletion", "nonce", "collection", "object", "returncode", "alias", "partial", "outcome", "report",
    "interpreter", "parameters"])
def test_resealed_tampering_cannot_change_accepted_interpretation(exchange: tuple,
        monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    from verifier.runtime import package_execution_observation as observation
    from verifier.core.receipt import strict_json_loads
    snapshot, item, selection = exchange

    def run(command: list[str], **kwargs: Any) -> Any:
        report = {"schema_version": ledger.OBSERVATION_SCHEMA,
            "request": strict_json_loads(kwargs["input"].decode()), "source_pins": {}, "observations": {"fact": 1}}
        return SimpleNamespace(returncode=0, stdout=canonical_bytes(report) + b"\n", stderr=b"")

    monkeypatch.setattr(execution.subprocess, "run", run)
    report = execution.execute_bound(snapshot, item, selection)
    trace = deepcopy(snapshot.execution_transports[(item.object_id, ledger.ADAPTER)])
    observation.verify_accepted(trace, report, selection=selection, item=item,
                                collection_digest=snapshot.collection_digest, module=ledger)
    if fault in {"stdout", "stdin", "stderr"}:
        trace[fault]["retained_base64"] = base64.b64encode(b"{}\n").decode()
    elif fault in {"selection", "pins"}:
        trace["selection_digest" if fault == "selection" else "source_pins_digest"] = "sha256:" + "f" * 64
    elif fault == "worker":
        trace["worker"] = "caller.py"
    elif fault == "flags":
        trace["flags"] = ["-B"]
    elif fault == "interpreter":
        trace["invoking_interpreter"] = False
    elif fault == "parameters":
        trace["parameters"]["timeout"] = 300
    elif fault == "environment":
        trace["environment_keys"].append("PYTHONPATH")
    elif fault == "environment-deletion":
        trace["environment_keys"].remove("TMPDIR")
    elif fault in {"nonce", "collection", "object"}:
        trace["request"][{"nonce": "nonce", "collection": "collection_digest", "object": "object_id"}[fault]] = "different"
    elif fault in {"returncode", "alias"}:
        trace["returncode"] = False if fault == "alias" else 1
    elif fault == "partial":
        trace["streams_complete"] = False
    elif fault == "outcome":
        trace["outcome"] = "TIMEOUT"
    elif fault == "report":
        report["observations"]["fact"] = 2
    if fault == "digest":
        trace["observation_digest"] = "sha256:" + "f" * 64
    else:
        trace = observation.seal({k: v for k, v in trace.items() if k != "observation_digest"})
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_PARENT_"):
        observation.verify_accepted(trace, report, selection=selection, item=item,
                                    collection_digest=snapshot.collection_digest, module=ledger)


def test_stderr_retention_is_not_claimed_complete_beyond_bound() -> None:
    from verifier.runtime import package_execution_observation as observation
    raw = b"diagnostic" * 10000
    value = observation.stream(raw, observation.STDERR_LIMIT)
    assert value["truncated"] is True and value["bytes"] == len(raw)
    assert base64.b64decode(value["retained_base64"]) == raw[:observation.STDERR_LIMIT]
    assert observation.stream(None, 1) is None
    assert observation.stream(b"", 1)["bytes"] == 0


def test_actual_installed_worker_capture_reaches_package_and_gate(declared_package: tuple) -> None:
    from test_package_ledger_execution import select_execution
    from test_package_kind_requirements import save
    from verifier.runtime import package_polish as package
    from verifier.runtime.manifest_gate import assess_object_gate
    from verifier.runtime import package_execution_observation as observation
    root, retained, _ = declared_package
    document = select_execution(root, retained)
    save(root, document)
    report = package.assess_package_polish(3, root)
    assert report["status"] == "UNKNOWN" and not report["polished"]
    traces = report["execution_observations"]
    assert len(traces) == 1, "Shared evidence is retained once, not duplicated for every obligation."
    own = [row for row in report["obligation_instances"] if row["selected_package_check"]
           and row["selected_package_check"].get("evidence_origin") == "SOURCE_BOUND_FRESH_EXECUTION"]
    assert len(own) == 12 and all(row["status"] == "PASS" for row in own)
    for row in own:
        check = row["selected_package_check"]
        assert check["parent_observation_digest"] == traces[0]["observation_digest"]
        record = next(record for record in report["package_graph"]["objects"] if record["object_id"] == row["object_id"])
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        observation.verify_accepted(traces[0], check["replay"], selection=check["selection"], item=item,
                                    collection_digest=report["package_graph"]["collection_digest"], module=ledger)
    gate = assess_object_gate("external", ledger.catalog()[0]["obligation_id"], root)
    assert gate["status"] == "PASS"
    trace = gate["execution_observations"][0]
    assert trace["request"]["nonce"] != traces[0]["request"]["nonce"]
    assert gate["instance"]["selected_package_check"]["parent_observation_digest"] == trace["observation_digest"]


