"""Actual manifest publication checks for Verifier Standard (VSTD).

The fixed worker may change only private fixture files. A manifest-provided
command or operator database is never executed. JavaScript Object Notation (JSON).
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from test_package_polish import declared_package
from test_manifest_gate import selected_root
from test_package_kind_requirements import prepare, save
from verifier.runtime.manifest_gate import obligation_catalog, assess_object_gate
from verifier.runtime.local_ledger_execution import validate_bindings
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime import manifest_write_execution as execution, package_polish as package, package_execution


NAMES = {
    "TRANSACTION-1.3-manifest-input-preconditions",
    "TRANSACTION-1.4-manifest-effect-scope",
    "TRANSACTION-2.3-manifest-publication-boundary",
    "TRANSACTION-2.4-manifest-partial-create",
    "TRANSACTION-3.3-manifest-retry-behavior",
    "TRANSACTION-3.4-manifest-concurrent-create",
}


def test_manifest_publication_has_registered_reasoned_routes() -> None:
    routes = {row["obligation_id"]: row for row in obligation_catalog()}
    assert NAMES <= routes.keys()
    assert all(routes[name]["reason"].strip() and routes[name]["exact_claim"].strip() for name in NAMES)


def test_manifest_writer_has_its_own_closed_execution_selection() -> None:
    selection: dict[str, Any] = {"object_id": "publication", "mechanism": "verifier-manifest-publication-1",
        "reason": "This implementation publishes the selected manifest; ledger state is a different variant.",
        "evidence": [{"path": "src/verifier/runtime/namespace_cli.py", "sha256": "sha256:" + "a" * 64}]}
    validate_bindings([selection], [{"object_id": "publication"}])


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {"schema_version": execution.REQUEST_SCHEMA, "nonce": "manifest-control-regression",
        "object_id": "publication", "object_digest": "sha256:" + "1" * 64, "collection_digest": "sha256:" + "2" * 64}
    result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode(), capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert report["request"] == request and report["source_pins"] == source_pins()
    return report["observations"]


@pytest.mark.parametrize("coordinate", ["TRANSACTION-1.3", "TRANSACTION-1.4", "TRANSACTION-2.3",
                                      "TRANSACTION-2.4", "TRANSACTION-3.3", "TRANSACTION-3.4"])
def test_actual_manifest_execution_satisfies_exact_finite_claim(observations: dict[str, Any], coordinate: str) -> None:
    assert execution.check_observations(coordinate, observations)


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("TRANSACTION-1.3", ("format", "after_preview"), "changed"),
    ("TRANSACTION-1.3", ("invalid", 0, "after"), "changed"),
    ("TRANSACTION-1.3", ("invalid", 1, "outcome", "exception"), None),
    ("TRANSACTION-1.3", ("format", "preview", "exit"), False),
    ("TRANSACTION-1.4", ("template", "after_preview_exists"), True),
    ("TRANSACTION-1.4", ("template", "published"), "{}\n"),
    ("TRANSACTION-1.4", ("template", "source_after"), "changed"),
    ("TRANSACTION-1.4", ("format", "sentinel"), "changed"),
    ("TRANSACTION-2.3", ("publication", "before", "after"), "changed"),
    ("TRANSACTION-2.3", ("publication", "after", "outcome", "exception"), None),
    ("TRANSACTION-2.3", ("publication", "before", "temporary_files"), ["leaked"]),
    ("TRANSACTION-2.3", ("publication", "race", "replace_calls"), 1),
    ("TRANSACTION-2.3", ("publication", "race", "replace_calls"), False),
    ("TRANSACTION-2.3", ("publication", "race", "after"), "overwritten"),
    ("TRANSACTION-2.4", ("partial", "outcome", "exception"), None),
    ("TRANSACTION-2.4", ("partial", "partial"), "{}\n"),
    ("TRANSACTION-2.4", ("partial", "writes"), 2),
    ("TRANSACTION-2.4", ("partial", "writes"), True),
    ("TRANSACTION-2.4", ("partial", "after_retry"), "overwritten"),
    ("TRANSACTION-3.3", ("template", "retry", "exit"), 0),
    ("TRANSACTION-3.3", ("template", "attempt_limit"), 2),
    ("TRANSACTION-3.3", ("template", "attempt_limit"), True),
    ("TRANSACTION-3.3", ("template", "publication_attempts", "retry"), 2),
    ("TRANSACTION-3.3", ("format", "after_second"), "changed"),
    ("TRANSACTION-3.3", ("format", "publication_attempts", "first"), 2),
    ("TRANSACTION-3.3", ("format", "temporary_files"), ["leaked"]),
    ("TRANSACTION-3.4", ("concurrent", "discoveries"), 1),
    ("TRANSACTION-3.4", ("concurrent", "attempt_limit"), 2),
    ("TRANSACTION-3.4", ("concurrent", "publication_attempts"), [1, 2]),
    ("TRANSACTION-3.4", ("concurrent", "outcomes"), [{"exit": 0, "exception": None}, {"exit": 0, "exception": None}]),
    ("TRANSACTION-3.4", ("concurrent", "outcomes"), [{"exit": False, "exception": None}, {"exit": True, "exception": None}]),
    ("TRANSACTION-3.4", ("concurrent", "published"), "{}\n"),
])
def test_state_oracle_refutes_wrong_effects(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    changed = deepcopy(observations)
    target = changed
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    assert not execution.check_observations(coordinate, changed)


def select_execution(root: Path, retained: dict[str, Any]) -> dict[str, Any]:
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    installed = Path(execution.__file__).parents[1]
    for relative in source_pins():
        target = root / "src/verifier" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / relative, target)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row.update(kind="TRANSACTION")
    row["surfaces"].append("file:" + execution.IMPLEMENTATION)
    document["namespace"]["execution_checks"] = [{"object_id": "external", "mechanism": execution.ADAPTER,
        "reason": "This object owns the actual manifest publication implementation; execute private file-boundary probes.",
        "evidence": [{"path": execution.IMPLEMENTATION,
            "sha256": package.binding.bytes_digest((root / execution.IMPLEMENTATION).read_bytes())}]}]
    save(root, document)
    return document


def test_selected_manifest_execution_reaches_package_and_focused_gates(declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, retained, _ = declared_package
    select_execution(root, retained)
    calls, execute = [], execution._execute

    def counted(*args: Any, **kwargs: Any) -> dict:
        calls.append(1)
        return execute(*args, **kwargs)

    monkeypatch.setattr(execution, "_execute", counted)
    report = package.assess_package_polish(3, root)
    rows = [row for row in report["obligation_instances"] if row["object_id"] == "external" and row["object_kind"] == "TRANSACTION"]
    own = [row for row in rows if row["coordinate"] in {item["coordinate"] for item in execution.catalog()}]
    other = [row for row in rows if row not in own]
    assert len(own) == len(other) == 6
    assert all(row["status"] == "PASS" for row in own), own
    assert all(row["status"] == "UNKNOWN" and row["selected_package_check"] is None for row in other)
    assert calls == [1] and report["status"] == "UNKNOWN" and not report["polished"]
    assert all(not row["native_specimen_is_instance_evidence"] for row in own)
    assert all(row["status"] == "UNKNOWN" for row in report["refinement_coverage"])
    gate = assess_object_gate("external", "TRANSACTION-2.3-manifest-publication-boundary", root)
    assert gate["status"] == "PASS", gate["findings"]
    assert calls == [1, 1]
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] != own[0]["selected_package_check"]["replay"]["request"]["nonce"]


@pytest.mark.parametrize("fault", ["unowned", "stale-source", "empty-reason", "unavailable", "stale-response"])
def test_selection_failures_never_borrow_a_pass(selected_root: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    document = select_execution(selected_root, json.loads((selected_root / "objects.vstd").read_bytes()))
    selected = document["namespace"]["execution_checks"][0]
    expected = "UNKNOWN"
    if fault == "unowned":
        next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")["surfaces"].remove("file:" + execution.IMPLEMENTATION)
    elif fault == "empty-reason":
        selected["reason"] = " "
    elif fault == "stale-source":
        selected["evidence"][0]["sha256"] = "sha256:" + "0" * 64
        expected = "FAIL"
    else:
        original = package_execution.subprocess.run

        def changed(command: list, *args: Any, **kwargs: Any) -> Any:
            result = original(command, *args, **kwargs)
            if str(command[-1]).endswith(execution.WORKER):
                if fault == "unavailable":
                    result.returncode = 2
                else:
                    value = json.loads(result.stdout)
                    value["request"]["nonce"] = "not-current"
                    result.stdout = package.binding.canonical_bytes(value)
            return result

        monkeypatch.setattr(package_execution.subprocess, "run", changed)
        if fault == "stale-response":
            expected = "FAIL"
    save(selected_root, document)
    report = assess_object_gate("external", "TRANSACTION-1.3-manifest-input-preconditions", selected_root)
    assert report["status"] == expected, report["findings"]


def test_unavailable_manifest_worker_is_attempted_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.core.namespace import NamespaceObject
    item = NamespaceObject.create("local", "OBJECT", {}, {})
    snapshot = SimpleNamespace(execution_checks={("local", execution.ADAPTER): {"mechanism": execution.ADAPTER}}, executions={}, execution_failures={},
                           collection_digest="sha256:" + "0" * 64)
    calls = []

    def unavailable(*args: Any) -> dict:
        calls.append(1)
        raise OSError("PACKAGE_EXECUTION_WORKER_UNAVAILABLE")

    monkeypatch.setattr(execution, "_execute", unavailable)
    assert all(package_execution.evaluate(snapshot, item, route)["status"] == "UNKNOWN" for route in execution.catalog())
    assert calls == [1]


def test_mechanism_selection_cannot_relabel_a_ledger_check() -> None:
    route = deepcopy(execution.catalog()[0])
    route["adapter"] = "verifier-local-invocation-ledger-1"
    with pytest.raises(ValueError, match="ROUTE_BINDING_DIFFERS"):
        package_execution.route_mechanism(route)


@pytest.mark.parametrize("operation,coordinate,target_name", [
    ("template", "TRANSACTION-1.4", "objects.vstd"),
    ("format", "TRANSACTION-1.4", "objects.vstd"),
    ("format", "TRANSACTION-3.3", "objects.vstd"),
    ("template", "TRANSACTION-3.4", "objects.vstd"),
    ("template", "TRANSACTION-1.4", "subject.py"),
    ("template", "TRANSACTION-3.4", "subject.py"),
])
def test_worker_keeps_byte_deviations_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        operation: str, coordinate: str, target_name: str) -> None:
    from verifier.runtime import manifest_write_worker as worker, namespace_cli
    original = getattr(namespace_cli, "handle_" + operation)

    def noncanonical(args: Any) -> int:
        result = original(args)
        if result == 0 and (not args.json if operation == "template" else args.write):
            target = Path(args.source_root) / target_name if operation == "template" else Path(args.manifest)
            target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
        return result

    monkeypatch.setattr(namespace_cli, "handle_" + operation, noncanonical)
    observed = worker.observe(tmp_path)
    assert not execution.check_observations(coordinate, observed)
