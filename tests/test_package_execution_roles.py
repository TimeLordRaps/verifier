"""Accumulating Verifier Standard (VSTD) roles retain separate execution evidence.

Pure cache tests isolate dispatch behavior. The package test below runs both real
installed workers against private fixtures; no live financial resources are used.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from test_package_polish import declared_package
from test_package_ledger_execution import select_execution
from test_package_kind_requirements import save
from verifier.core.namespace import NamespaceObject
from verifier.runtime import local_ledger_worker, package_execution, package_polish as package
from verifier.runtime import local_ledger_execution as ledger, manifest_write_execution as manifest
from verifier.runtime.manifest_gate import assess_object_gate


def bindings(identifier: str = "local") -> list[dict[str, Any]]:
    return [{"object_id": identifier, "mechanism": module.ADAPTER,
        "reason": "This role requires its separately bound installed execution.",
        "evidence": [{"path": module.IMPLEMENTATION, "sha256": "sha256:" + "a" * 64}]}
        for module in (ledger, manifest)]


def test_one_object_can_select_distinct_installed_mechanisms() -> None:
    package_execution.validate_bindings(bindings(), [{"object_id": "local"}])


def test_package_only_route_applies_only_to_its_exact_source_owner() -> None:
    route = ledger.catalog()[0]
    owner = {"surfaces": ["file:" + ledger.IMPLEMENTATION]}
    unrelated = {"surfaces": ["file:src/verifier/runtime/unrelated.py"]}
    assert package_execution.owns_route_implementation(owner, route) is True
    assert package_execution.owns_route_implementation(unrelated, route) is False


def test_duplicate_pair_is_rejected_even_when_reason_or_evidence_differs() -> None:
    selected = bindings()
    duplicate = deepcopy(selected[0])
    duplicate["reason"] = "A changed reason cannot select an ambiguous second execution."
    selected.append(duplicate)
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_"):
        package_execution.validate_bindings(selected, [{"object_id": "local"}])


def test_admission_binds_all_selected_roles_without_running_any_worker(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    from test_namespace_admission import repository, completed_manifest
    from verifier.runtime.namespace_admission import assess
    from verifier.runtime.namespace_contracts import namespace_registry
    root = repository(tmp_path, "def calculate(): pass\n")
    for module in (ledger, manifest):
        path = root / module.IMPLEMENTATION
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("def calculate(): pass\n", encoding="utf-8")
    document = completed_manifest(root, "")
    owner = next(row for row in document["objects"] if "file:accounts.py" in row["surfaces"])
    owner["surfaces"] = [surface for row in document["objects"] for surface in row["surfaces"]]
    document["objects"] = [owner]
    document["execution_checks"] = bindings(owner["object_id"])
    for selection in document["execution_checks"]:
        reference = selection["evidence"][0]
        reference["sha256"] = package.binding.bytes_digest((root / reference["path"]).read_bytes())
    save(root, document)

    def forbidden(*args: Any, **kwargs: Any) -> dict:
        raise AssertionError("Admission cannot execute a selected worker.")

    for module in (ledger, manifest):
        monkeypatch.setattr(module, "_execute", forbidden)
    result = assess(root)
    # The collapsed fixture supplies no applicability reasons or refutations, so admission must stay
    # UNKNOWN. Binding both roles is still required and proven; only the missing applicability is reported.
    assert result["status"] == "UNKNOWN"
    assert result["independent_reconciliation"]["status"] == "PASS"
    findings = result["findings"]
    assert {finding["code"] for finding in findings} == {
        "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
    }
    expected_kinds = set(namespace_registry()) - {"OBJECT"}
    assert len(findings) == len(expected_kinds) == 37, findings
    assert {
        finding["explanation"].partition(" declares DOES_NOT_APPLY")[0]
        for finding in findings
    } == expected_kinds
    assert len(result["execution_bindings"]) == 2
    assert all(row["status"] == "PASS" and row["semantic_fulfillment"] == "NOT_ESTABLISHED"
               for row in result["execution_bindings"])


INTEGRITY_UNCERTAIN = ("UNKNOWN", "PACKAGE_EXECUTION_CHECKER_INTEGRITY_UNCERTAIN")


@pytest.mark.parametrize("bad", [ledger, manifest], ids=["ledger", "manifest"])
@pytest.mark.parametrize("fault,expected", [
    # A worker fault is typed before any checker runs.
    ("unavailable", ("UNKNOWN", "PACKAGE_EXECUTION_WORKER_UNAVAILABLE")),
    # A request-binding difference is a parent-side semantic refusal, not a checker verdict.
    ("invalid", ("FAIL", "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")),
    # A parent-substituted refutation must not become FAIL; the isolated child checker cannot see it.
    ("refuted", INTEGRITY_UNCERTAIN),
])
def test_failures_and_passes_are_isolated_by_object_and_mechanism(monkeypatch: pytest.MonkeyPatch,
        bad: Any, fault: str, expected: tuple[str, str]) -> None:
    # The live tree is edited concurrently; a fixed pin set keeps the cache-count assertions about dispatch alone.
    monkeypatch.setattr(local_ledger_worker, "source_pins", lambda: {"runtime/alpha.py": "sha256:" + "1" * 64})
    items = [NamespaceObject.create(identifier, "OBJECT", {}, {}) for identifier in ("first", "second")]
    selected = bindings("first") + bindings("second")
    snapshot = SimpleNamespace(execution_checks={(row["object_id"], row["mechanism"]): row for row in selected},
        executions={}, execution_failures={}, execution_transports={}, collection_digest="sha256:" + "c" * 64)
    calls: Counter = Counter()
    parent_verdicts: list[str] = []

    def install(module: Any) -> None:
        def execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
            calls[(item.object_id, module.ADAPTER)] += 1
            if item.object_id == "first" and module is bad:
                if fault == "unavailable":
                    raise OSError("PACKAGE_EXECUTION_WORKER_UNAVAILABLE")
                if fault == "invalid":
                    raise ValueError("PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")
            # This is an explicit synthetic cache-control fixture. Real capture
            # and its integrity guard are exercised without this stub elsewhere.
            from verifier.runtime import package_execution_observation as observation
            from verifier.runtime.tier_zero_profile import canonical_bytes
            import sys
            from verifier.runtime.local_ledger_worker import source_pins
            # Revalidation binds a cached receipt to the current source bytes, so the
            # synthetic exchange must carry the same pins a real launch would report.
            pins = source_pins()
            request = {"schema_version": module.REQUEST_SCHEMA, "nonce": "d" * 64,
                "object_id": item.object_id, "object_digest": item.digest, "collection_digest": snapshot.collection_digest}
            report = {"schema_version": module.OBSERVATION_SCHEMA, "request": request, "source_pins": pins,
                "observations": {"adapter": module.ADAPTER, "object": item.object_id,
                    "valid": not (item.object_id == "first" and module is bad and fault == "refuted")}}
            # The synthetic trace must retain the same private temporary-root
            # contract as a real worker launch.  Empty values are sufficient
            # here because the parent observation records environment keys,
            # never workstation paths or host-specific values.
            trace = observation.begin(request, selection, pins, [sys.executable, "-I", "-S", "-B", module.WORKER],
                {"env": {name: "" for name in ("TEMP", "TMP", "TMPDIR")},
                 "input": canonical_bytes(request), "capture_output": True, "timeout": 30, "check": False})
            trace.update(outcome="ACCEPTED", returncode=0, streams_complete=True,
                stdout=observation.stream(canonical_bytes(report), observation.OUTPUT_LIMIT),
                stderr=observation.stream(b"", observation.STDERR_LIMIT))
            snapshot.execution_transports[(item.object_id, module.ADAPTER)] = observation.seal(trace)
            return report

        def substitute(coordinate: str, observed: dict[str, Any]) -> bool:
            # A parent-process verdict is the forbidden path; production never reaches it.
            parent_verdicts.append(coordinate)
            return observed["adapter"] == module.ADAPTER and observed["valid"]

        monkeypatch.setattr(module, "_execute", execute)
        monkeypatch.setattr(module, "check_observations", substitute)

    for module in (ledger, manifest):
        install(module)
    for item in items:
        for module in (bad, manifest if bad is ledger else ledger):
            for route in module.catalog():
                result = package_execution.evaluate(snapshot, item, route)
                assert result is not None
                assert result["selection"]["mechanism"] == module.ADAPTER
                if item.object_id == "first" and module is bad:
                    assert (result["status"], result["reason"]) == expected
                else:
                    # Unaffected rows never inherit the fault, and the substitute never becomes PASS.
                    assert (result["status"], result["reason"]) == INTEGRITY_UNCERTAIN
                # No refused, unavailable or substituted row retains executed evidence or applicability.
                assert result["replay"] is None and result["applicability_established"] is False
    assert calls == Counter({(item.object_id, module.ADAPTER): 1 for item in items for module in (ledger, manifest)})
    assert parent_verdicts == [], "The parent-process replacement must never be called as the checker."


def test_real_two_mechanism_object_keeps_package_and_focused_evidence_separate(
        declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, retained, _ = declared_package
    document = select_execution(root, retained)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row["surfaces"].append("file:" + manifest.IMPLEMENTATION)
    second = bindings("external")[1]
    second["evidence"][0]["sha256"] = package.binding.bytes_digest((root / manifest.IMPLEMENTATION).read_bytes())
    document["namespace"]["execution_checks"].append(second)
    save(root, document)
    calls: Counter = Counter()

    def observe(module: Any) -> None:
        original = module._execute

        def counted(*args: Any, **kwargs: Any) -> dict[str, Any]:
            calls[module.ADAPTER] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(module, "_execute", counted)

    for module in (ledger, manifest):
        observe(module)
    result = package.assess_package_polish(3, root)
    routes = {route["coordinate"]: route for module in (ledger, manifest) for route in module.catalog()}
    rows = [row for row in result["obligation_instances"] if row["object_id"] == "external" and row["coordinate"] in routes]
    assert len(rows) == 18 and all(row["status"] == "PASS" for row in rows), result["blockers"]
    assert calls == Counter({ledger.ADAPTER: 1, manifest.ADAPTER: 1})
    nonces: dict[str, set[str]] = {ledger.ADAPTER: set(), manifest.ADAPTER: set()}
    for row in rows:
        adapter = routes[row["coordinate"]]["adapter"]
        check = row["selected_package_check"]
        assert check["selection"]["mechanism"] == adapter
        request = check["replay"]["request"]
        assert request["object_id"] == "external" and request["object_digest"] == row["object_digest"]
        assert request["collection_digest"] == result["package_graph"]["collection_digest"]
        nonces[adapter].add(request["nonce"])
    assert all(len(values) == 1 for values in nonces.values())
    assert nonces[ledger.ADAPTER].isdisjoint(nonces[manifest.ADAPTER])
    assert result["status"] == "UNKNOWN" and not result["polished"]
    gate = assess_object_gate("external", manifest.catalog()[0]["obligation_id"], root)
    assert gate["status"] == "PASS", gate["findings"]
    assert calls == Counter({ledger.ADAPTER: 1, manifest.ADAPTER: 2}), "The focused route may launch only its own mechanism."
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] not in nonces[manifest.ADAPTER]


def test_request_binding_declaration_matches_every_checker_signature() -> None:
    """Only declared adapters receive ``request=``; the declaration cannot drift from the checker."""
    for module in package_execution.mechanisms().values():
        accepts = "request" in inspect.signature(module.check_observations).parameters
        assert (module.ADAPTER in package_execution.REQUEST_BOUND_ADAPTERS) is accepts, module.ADAPTER


def test_uninstalled_in_process_checker_cannot_supply_a_verdict() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def legacy(coordinate: str, observed: dict[str, Any]) -> bool:
        calls.append((coordinate, observed))
        return True

    module = SimpleNamespace(ADAPTER="undeclared-legacy-1", check_observations=legacy)
    executed = {"observations": {"value": 1}, "request": {"nonce": "unused"}}
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_SOURCE_UNAVAILABLE"):
        package_execution.check_executed(module, "LEGACY-1.1", executed)
    assert calls == []


def test_uninstalled_declared_checker_is_not_executed_in_process(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A synthetic callable is unavailable, never a fallback execution path."""
    def defective(coordinate: str, observed: dict[str, Any], request: dict[str, Any]) -> bool:
        raise TypeError("checker defect")

    module = SimpleNamespace(ADAPTER="declared-bound-1", CHECKER_CONTRACT="request-bound", check_observations=defective)
    monkeypatch.setattr(package_execution, "REQUEST_BOUND_ADAPTERS", frozenset({"declared-bound-1"}))
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_SOURCE_UNAVAILABLE"):
        package_execution.check_executed(module, "BOUND-1.1", {"observations": {}, "request": {}})


def test_declared_adapter_without_executed_request_is_refused_not_self_checked(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Self-consistency alone accepts any request's observations, so absence must fail closed."""
    calls: list[Any] = []

    def checker(coordinate: str, observed: dict[str, Any], request: dict[str, Any]) -> bool:
        calls.append(request)
        return True

    module = SimpleNamespace(ADAPTER="declared-bound-1", CHECKER_CONTRACT="request-bound", check_observations=checker)
    monkeypatch.setattr(package_execution, "REQUEST_BOUND_ADAPTERS", frozenset({"declared-bound-1"}))
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_REQUEST_ABSENT"):
        package_execution.check_executed(module, "BOUND-1.1", {"observations": {}})
    assert calls == []
