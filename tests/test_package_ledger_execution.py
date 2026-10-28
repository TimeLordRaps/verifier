"""Specialized Verifier Standard (VSTD) checks must reach actual package code."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from test_package_kind_requirements import prepare, save
from test_package_polish import declared_package
from test_manifest_gate import selected_root
from verifier.runtime import package_polish as package
from verifier.runtime.manifest_gate import assess_object_gate, obligation_catalog
from verifier.runtime import local_ledger_execution as execution
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.package_instance_evidence import InstanceEvidence


def ledger_subject(root: Path, retained: dict) -> dict:
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    (root / "subject.py").write_text("__vstd_kinds__ = ['LEDGER', 'TRANSACTION']\nraise RuntimeError('never run subject')\n", encoding="utf-8")
    save(root, document)
    return document


def test_specialized_ledger_and_transaction_routes_have_reasons_and_exact_names() -> None:
    catalog = obligation_catalog()
    selected = [row for row in catalog if row["object_kind"] in {"LEDGER", "TRANSACTION"}]
    assert {(row["object_kind"], row["tier"]) for row in selected} == {
        (kind, tier) for kind in ("LEDGER", "TRANSACTION") for tier in (1, 2, 3)}
    assert all(row["reason"].strip() and row["exact_claim"].strip() for row in selected)


def test_ledger_accounting_route_names_every_admission_surface() -> None:
    route = next(row for row in execution.catalog() if row["coordinate"] == "LEDGER-2.1")
    text = (route["reason"] + " " + route["exact_claim"]).lower()
    for required in ("unit", "balance", "round", "source", "sink"):
        assert required in text


def test_generic_label_does_not_hide_specialized_requirements(declared_package: tuple) -> None:
    root, retained, _ = declared_package
    ledger_subject(root, retained)
    report = package.assess_package_polish(3, root)
    rows = [row for row in report["obligation_instances"] if row["object_id"] == "external"
            and row["object_kind"] in {"LEDGER", "TRANSACTION"}]
    assert len(rows) == 18
    assert all(row["status"] == "UNKNOWN" for row in rows)
    assert all(row["kind_requirement"]["necessity"] == "NECESSARY" for row in rows)
    assert not report["polished"]


def test_unselected_execution_is_unknown_and_never_launches_subject(selected_root: Path) -> None:
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    ledger_subject(selected_root, retained)
    result = assess_object_gate("external", "LEDGER-1.1-local-record-identity", selected_root)
    assert result["status"] == "UNKNOWN", result["findings"]
    assert result["instance"]["checker_status"] == "NOT_RUN"
    assert result["instance"]["object_kind"] == "LEDGER"


def select_execution(root: Path, retained: dict) -> dict:
    document = ledger_subject(root, retained)
    installed = Path(execution.__file__).parents[1]
    for relative in source_pins():
        target = root / "src/verifier" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / relative, target)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row.update(kind="LEDGER", specializations=["TRANSACTION"])
    row["surfaces"].append("file:" + execution.IMPLEMENTATION)
    document["namespace"]["execution_checks"] = [{"object_id": "external", "mechanism": execution.ADAPTER,
        "reason": "This object's owned source implements the local invocation ledger; exercise its exact installed bytes without touching operator state.",
        "evidence": [{"path": execution.IMPLEMENTATION,
                      "sha256": package.binding.bytes_digest((root / execution.IMPLEMENTATION).read_bytes())}]}]
    save(root, document)
    return document


def test_real_selected_execution_has_package_and_focused_gates(declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, retained, _ = declared_package
    document = select_execution(root, retained)
    calls = []
    execute = execution._execute

    def counted(*args: Any, **kwargs: Any) -> dict:
        calls.append(1)
        return execute(*args, **kwargs)

    monkeypatch.setattr(execution, "_execute", counted)
    report = package.assess_package_polish(3, root)
    selected = [row for row in report["obligation_instances"] if row["object_id"] == "external"
                and row["object_kind"] in {"LEDGER", "TRANSACTION"}]
    ledger_coordinates = {route["coordinate"] for route in execution.catalog()}
    own = [row for row in selected if row["coordinate"] in ledger_coordinates]
    other = [row for row in selected if row["coordinate"] not in ledger_coordinates]
    assert len(own) == 12 and all(row["status"] == "PASS" for row in own), own
    assert len(other) == 6 and all(row["status"] == "UNKNOWN" and row["selected_package_check"] is None for row in other)
    assert calls == [1], "One source-bound execution serves all predicates without repeated launches."
    assert all(row["selected_package_check"]["replay"]["request"]["collection_digest"]
               == report["package_graph"]["collection_digest"] for row in own)
    assert all(not row["native_specimen_is_instance_evidence"] for row in selected)
    assert all(row["status"] == "UNKNOWN" for row in report["refinement_coverage"])
    assert report["status"] == "UNKNOWN", report["findings"]
    assert not report["polished"]
    gate = assess_object_gate("external", "LEDGER-1.1-local-record-identity", root)
    assert gate["status"] == "PASS", gate["findings"]
    assert calls == [1, 1], "A new assessment must execute afresh."
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] != selected[0]["selected_package_check"]["replay"]["request"]["nonce"]


@pytest.mark.parametrize("fault", ["stale-source", "unowned-source", "empty-reason", "worker-unavailable", "stale-response"])
def test_execution_never_borrows_a_pass_when_binding_is_unavailable(selected_root: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    document = select_execution(selected_root, retained)
    expected = "UNKNOWN"
    if fault == "stale-source":
        with (selected_root / execution.IMPLEMENTATION).open("ab") as stream:
            stream.write(b"\n# Current repository bytes differ from the selected implementation.\n")
        expected = "FAIL"
    elif fault == "unowned-source":
        next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")["surfaces"].remove("file:" + execution.IMPLEMENTATION)
    elif fault == "empty-reason":
        document["namespace"]["execution_checks"][0]["reason"] = " "
    else:
        original = execution.subprocess.run

        def changed(command: list, *args: Any, **kwargs: Any) -> Any:
            result = original(command, *args, **kwargs)
            if str(command[-1]).endswith("local_ledger_worker.py"):
                if fault == "worker-unavailable":
                    result.returncode = 2
                else:
                    value = json.loads(result.stdout)
                    value["request"]["nonce"] = "stale"
                    result.stdout = package.binding.canonical_bytes(value)
            return result

        monkeypatch.setattr(execution.subprocess, "run", changed)
        if fault == "stale-response":
            expected = "FAIL"
    save(selected_root, document)
    result = assess_object_gate("external", "LEDGER-1.1-local-record-identity", selected_root)
    assert result["status"] == expected, result["findings"]
    assert result["instance"]["selected_package_check"]["status"] == expected
    reasons = {"stale-source": "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS",
        "unowned-source": "PACKAGE_EXECUTION_OWNED_IMPLEMENTATION_UNAVAILABLE",
        "empty-reason": "PACKAGE_EXECUTION_SOURCE_REASON_UNAVAILABLE",
        "worker-unavailable": "PACKAGE_EXECUTION_WORKER_UNAVAILABLE",
        "stale-response": "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS"}
    assert result["instance"]["selected_package_check"]["reason"] == reasons[fault]


def test_status_words_do_not_replace_persisted_effects(selected_root: Path) -> None:
    retained = json.loads((selected_root / "objects.vstd").read_bytes())
    document = select_execution(selected_root, retained)
    objects = package.package_manifest.validate_bridge(document)
    item = next(item for item in objects if item.object_id == "external")
    snapshot = InstanceEvidence(selected_root, objects, document["namespace"])
    actual = execution._execute(snapshot, item, document["namespace"]["execution_checks"][0])["observations"]
    mutations = {
        "LEDGER-1.1": lambda value: value["records"]["first_rows"].clear(),
        "LEDGER-2.1": lambda value: value["records"]["duplicate_rows"].append(deepcopy(value["records"]["first_rows"][0])),
        "LEDGER-3.1": lambda value: value["faults"]["after"]["after_recovery"].clear(),
        "TRANSACTION-1.1": lambda value: value["preconditions"]["rows"].append({"unauthorized": True}),
        "TRANSACTION-2.1": lambda value: value["faults"]["after"]["before_recovery"].clear(),
        "TRANSACTION-3.1": lambda value: value["epochs"]["rows"].clear(),
    }
    for coordinate, mutate in mutations.items():
        assert execution.check_observations(coordinate, actual)
        altered = deepcopy(actual)
        mutate(altered)
        assert not execution.check_observations(coordinate, altered)


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("records", "first", "commit_sequence"), 7),
        (("records", "first", "proposal_digest"), "sha256:" + "0" * 64),
        (("records", "second", "commit_sequence"), 1),
        (("records", "second", "invocation_id"), "a"),
    ],
)
def test_accounting_invariant_route_binds_receipts_to_exact_record_units(
    tmp_path: Path, path: tuple[str, ...], replacement: Any
) -> None:
    """LEDGER-0.2 cannot pass from row counts while its receipts disagree."""
    from verifier.runtime.local_ledger_worker import observe

    observed = observe(tmp_path)
    changed = deepcopy(observed)
    row: Any = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    assert not execution.check_observations("LEDGER-2.1", changed)


def test_unavailable_worker_is_attempted_once_for_all_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.core.namespace import NamespaceObject
    item = NamespaceObject.create("local", "OBJECT", {}, {})
    selection = {"object_id": "local", "mechanism": execution.ADAPTER, "reason": "Selected test mechanism.", "evidence": []}
    snapshot = SimpleNamespace(
        collection_digest="sha256:" + "c" * 64,
        execution_checks={("local", execution.ADAPTER): selection},
        executions={},
        execution_failures={},
        execution_transports={},
    )
    calls = []

    def unavailable(*args: Any, **kwargs: Any) -> dict:
        calls.append(1)
        raise OSError("PACKAGE_EXECUTION_WORKER_UNAVAILABLE")

    monkeypatch.setattr(execution, "_execute", unavailable)
    results = [execution.evaluate(snapshot, item, route) for route in execution.catalog()]
    assert calls == [1]
    assert all(row["status"] == "UNKNOWN" and not row["applicability_established"] for row in results)


@pytest.mark.parametrize("mutation", [
    lambda rows: rows[0].update(command="arbitrary-command"),
    lambda rows: rows[0].update(mechanism="unregistered-worker"),
    lambda rows: rows[0].update(object_id="missing"),
    lambda rows: rows.append(deepcopy(rows[0])),
    lambda rows: rows[0]["evidence"][0].update(path="../outside.py"),
])
def test_execution_selection_is_closed_and_never_accepts_a_command(mutation: Callable) -> None:
    bindings = [{"object_id": "local", "mechanism": execution.ADAPTER, "reason": "Bounded source selection.",
                 "evidence": [{"path": "local.py", "sha256": "sha256:" + "a" * 64}]}]
    mutation(bindings)
    with pytest.raises(ValueError, match="PACKAGE_"):
        execution.validate_bindings(bindings, [{"object_id": "local"}])


@pytest.mark.parametrize("adapter", ["ledger", "manifest"])
@pytest.mark.parametrize("fault", ["none", "empty-reason", "unowned-source", "stale-source"])
def test_admission_checks_execution_bindings_without_executing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        adapter: str, fault: str) -> None:
    from test_namespace_admission import repository, completed_manifest
    from verifier.runtime.namespace_admission import assess
    from verifier.runtime import local_ledger_execution, manifest_write_execution
    execution = {"ledger": local_ledger_execution, "manifest": manifest_write_execution}[adapter]
    root = repository(tmp_path, "def calculate(): pass\n")
    source = root / execution.IMPLEMENTATION
    source.parent.mkdir(parents=True)
    source.write_text("def calculate(): pass\n", encoding="utf-8")
    document = completed_manifest(root, "")
    owner = next(row for row in document["objects"] if "file:" + execution.IMPLEMENTATION in row["surfaces"])
    selection = {"object_id": owner["object_id"], "mechanism": execution.ADAPTER,
        "reason": "Bind this source for a later explicit execution; admission does not validate its behavior.",
        "evidence": [{"path": execution.IMPLEMENTATION, "sha256": package.binding.bytes_digest(source.read_bytes())}]}
    document["execution_checks"] = [selection]
    if fault == "empty-reason":
        selection["reason"] = " "
    elif fault == "unowned-source":
        selection["object_id"] = next(row["object_id"] for row in document["objects"] if "file:accounts.py" in row["surfaces"])
    elif fault == "stale-source":
        selection["evidence"][0]["sha256"] = "sha256:" + "0" * 64
    save(root, document)

    def forbidden(*args: Any, **kwargs: Any) -> dict:
        raise AssertionError("Admission must not launch a fresh execution.")

    monkeypatch.setattr(execution, "_execute", forbidden)
    report = assess(root)
    binding = report["execution_bindings"][0]
    assert binding["status"] == {"none": "PASS", "empty-reason": "UNKNOWN", "unowned-source": "UNKNOWN", "stale-source": "FAIL"}[fault]
    assert binding["semantic_fulfillment"] == "NOT_ESTABLISHED"
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert any(row["code"] == "PACKAGE_EXECUTION_SOURCE_UNRESOLVED" for row in report["findings"]) == (fault != "none")
