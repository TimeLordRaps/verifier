"""Adversarial checks for the fresh package-checker source boundary."""
from __future__ import annotations

import importlib.util
import json
import py_compile
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from verifier.core import owned_process
from verifier.core.namespace import NamespaceObject
from verifier.runtime import (
    emulator_control_execution,
    manifest_write_execution,
    package_execution,
)
from verifier.runtime.local_ledger_worker import source_pins


def _fixture_module(path: Path, source: str) -> ModuleType:
    module = ModuleType("verifier.runtime.fixture_checker_execution")
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    exec(
        compile(
            source,
            str(path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        ),
        module.__dict__,
    )
    return module


def _normally_imported_fixture_module(path: Path) -> ModuleType:
    """Load source through Python's ordinary source loader, without caller flags."""

    name = "verifier.runtime.fixture_checker_execution"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> tuple[ModuleType, Path]:
    root = tmp_path / "src"
    runtime = root / "verifier" / "runtime"
    runtime.mkdir(parents=True)
    (root / "verifier" / "__init__.py").write_text("", encoding="utf-8")
    (runtime / "__init__.py").write_text("", encoding="utf-8")
    path = runtime / "fixture_checker_execution.py"
    path.write_text(source, encoding="utf-8")
    module = _fixture_module(path, source)
    monkeypatch.setattr(
        package_execution,
        "_checker_source",
        lambda _module: (root, path, "verifier/runtime/fixture_checker_execution.py"),
    )
    return module, path


def _source(body: str) -> str:
    return (
        "ADAPTER = 'fixture-checker-1'\n"
        "def check_observations(coordinate, observed):\n"
        f"    {body}\n"
    )


def test_checker_uses_current_source_not_a_stale_same_process_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = _source("return 1 == 1")
    module, path = _fixture_tree(tmp_path, monkeypatch, old)
    path.write_text(_source("return 1 == 0"), encoding="utf-8")

    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_"):
        package_execution.check_executed(module, "OBJECT-1.1", {"observations": {}})


def test_checker_ignores_stale_bytecode_and_executes_held_current_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = _source("return 1 == 1")
    module, path = _fixture_tree(tmp_path, monkeypatch, stale)
    py_compile.compile(str(path), doraise=True)
    current = _source("return 1 == 0")
    path.write_text(current, encoding="utf-8")
    module = _fixture_module(path, current)

    assert package_execution.check_executed(
        module, "OBJECT-1.1", {"observations": {}}
    ) is False


def test_source_bound_exact_true_keeps_semantic_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _ = _fixture_tree(tmp_path, monkeypatch, _source("return True"))
    assert package_execution.check_executed(
        module, "OBJECT-1.1", {"observations": {}}
    ) is True


def test_normally_imported_no_future_checker_keeps_source_only_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source("return True")
    module, path = _fixture_tree(tmp_path, monkeypatch, source)
    module = _normally_imported_fixture_module(path)

    assert package_execution.check_executed(
        module, "OBJECT-1.1", {"observations": {}}
    ) is True


def test_normally_imported_nested_checker_has_stable_source_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (
        "ADAPTER = 'fixture-checker-1'\n"
        "def check_observations(coordinate, observed):\n"
        "    allowed = frozenset({'before', 'after', 'race'})\n"
        "    return (all(row['before'] in allowed for row in observed['rows'])\n"
        "            and all(row['after'] in allowed for row in observed['rows']))\n"
    )
    _module, path = _fixture_tree(tmp_path, monkeypatch, source)
    py_compile.compile(str(path), doraise=True)
    module = _normally_imported_fixture_module(path)

    assert package_execution.check_executed(
        module,
        "OBJECT-1.1",
        {"observations": {"rows": [{"before": "before", "after": "after"}]}},
    ) is True


def test_code_digest_ignores_marshaled_reference_aliasing() -> None:
    path = Path(manifest_write_execution.__file__).resolve(strict=True)
    held = _fixture_module(path, path.read_text(encoding="utf-8"))
    assert (
        manifest_write_execution.check_observations.__code__
        == held.check_observations.__code__
    )
    assert package_execution._code_digest(
        manifest_write_execution.check_observations
    ) == package_execution._code_digest(held.check_observations)


def test_checker_source_change_during_execution_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (
        "ADAPTER = 'fixture-checker-1'\n"
        "def check_observations(coordinate, observed):\n"
        "    from pathlib import Path\n"
        "    Path(__file__).write_text('# changed\\n', encoding='utf-8')\n"
        "    return True\n"
    )
    module, _ = _fixture_tree(tmp_path, monkeypatch, source)
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_"):
        package_execution.check_executed(module, "OBJECT-1.1", {"observations": {}})


def test_in_process_checker_swap_is_integrity_unknown_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        emulator_control_execution,
        "check_observations",
        lambda coordinate, observed, request: True,
    )
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_"):
        package_execution.check_executed(
            emulator_control_execution,
            "CONTROLLER-1.1",
            {"observations": {}, "request": {}},
        )


@pytest.mark.parametrize(
    "body",
    ["return 'truthy'", "raise RuntimeError('private checker defect')"],
)
def test_checker_defect_or_non_boolean_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
) -> None:
    module, _ = _fixture_tree(tmp_path, monkeypatch, _source(body))
    with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_") as caught:
        package_execution.check_executed(module, "OBJECT-1.1", {"observations": {}})
    assert "private checker defect" not in str(caught.value)


@pytest.mark.parametrize(
    "result,code",
    [
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_TIMEOUT,
                owned_process.CLEANUP_CONFIRMED,
                None,
                b"",
                b"",
                False,
                False,
            ),
            "PACKAGE_EXECUTION_CHECKER_TIMEOUT",
        ),
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_OUTPUT_CAP,
                owned_process.CLEANUP_CONFIRMED,
                None,
                b"",
                b"",
                True,
                False,
            ),
            "PACKAGE_EXECUTION_CHECKER_OUTPUT_CAPACITY",
        ),
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_EXITED,
                owned_process.CLEANUP_NOT_CONFIRMED,
                0,
                b"{}",
                b"",
                False,
                False,
            ),
            "PACKAGE_EXECUTION_CHECKER_CLEANUP_NOT_CONFIRMED",
        ),
    ],
)
def test_checker_process_outcomes_remain_typed_unknown(
    monkeypatch: pytest.MonkeyPatch,
    result: owned_process.OwnedProcessResult,
    code: str,
) -> None:
    monkeypatch.setattr(package_execution, "_run_package_checker", lambda *args: result)
    with pytest.raises(OSError, match=code):
        package_execution.check_executed(
            emulator_control_execution,
            "CONTROLLER-1.1",
            {"observations": {}, "request": {}},
        )


def _closed_forged_checker_result(
    command: list[str], parameters: dict[str, Any], **changes: Any
) -> Any:
    """Build an otherwise exact receipt for testing the parent process gate."""

    payload = json.loads(parameters["input"])
    worker_digest = package_execution._sha256(Path(command[-2]).read_bytes())
    receipt = {
        "schema_version": "verifier-package-checker-receipt-1",
        "request_digest": package_execution.value_digest(payload),
        "adapter": payload["adapter"],
        "coordinate": payload["coordinate"],
        "contract": payload["contract"],
        "checker_relative": payload["checker_relative"],
        "checker_sha256_before": payload["checker_sha256"],
        "checker_sha256_after": payload["checker_sha256"],
        "loaded_checker_code_sha256": payload["loaded_checker_code_sha256"],
        "loaded_checker_contract": payload["loaded_checker_contract"],
        "worker_sha256_before": worker_digest,
        "worker_sha256_after": worker_digest,
        "status": "PASS",
        "reason": "PACKAGE_EXECUTION_CHECKER_ACCEPTED",
        "verdict": True,
    }
    fields: dict[str, Any] = {
        "status": owned_process.STATUS_EXITED,
        "cleanup": owned_process.CLEANUP_CONFIRMED,
        "returncode": 0,
        "stdout": package_execution.canonical_bytes(receipt),
        "stderr": b"",
        "stdout_overflowed": False,
        "stderr_overflowed": False,
    }
    overridden_complete = changes.pop("streams_complete", None)
    fields.update(changes)
    result = owned_process.OwnedProcessResult(**fields)
    if overridden_complete is None:
        return result
    return SimpleNamespace(
        **{name: getattr(result, name) for name in fields},
        streams_complete=overridden_complete,
    )


class _SelectiveEqualitySpoof:
    """A non-string that claims equality only with one trusted enum value."""

    def __init__(self, accepted: str) -> None:
        self._accepted = accepted

    def __eq__(self, other: object) -> bool:
        return other == self._accepted


class _DelegatedProcessResult:
    """Expose the closed process-result field set without dynamic delegation."""

    def __init__(self, result: Any) -> None:
        self._result = result

    @property
    def status(self) -> Any:
        return self._result.status

    @property
    def cleanup(self) -> Any:
        return self._result.cleanup

    @property
    def returncode(self) -> Any:
        return self._result.returncode

    @property
    def stdout(self) -> Any:
        return self._result.stdout

    @property
    def stderr(self) -> Any:
        return self._result.stderr

    @property
    def stdout_overflowed(self) -> Any:
        return self._result.stdout_overflowed

    @property
    def stderr_overflowed(self) -> Any:
        return self._result.stderr_overflowed


class _ExplodingStreamsResult(_DelegatedProcessResult):
    """Delegate the receipt fields but fail while completeness is observed."""

    @property
    def streams_complete(self) -> bool:
        raise RuntimeError("hostile streams_complete property")


class _CountingStreamsResult(_DelegatedProcessResult):
    """Expose whether the parent observes completeness more than once."""

    def __init__(self, result: Any) -> None:
        super().__init__(result)
        self.streams_complete_reads = 0

    @property
    def streams_complete(self) -> bool:
        self.streams_complete_reads += 1
        return True


_PROCESS_MUTANTS = (
    ({"status": "MYSTERY"}, "PACKAGE_EXECUTION_CHECKER_STATUS_UNKNOWN"),
    ({"cleanup": "BOGUS"}, "PACKAGE_EXECUTION_CHECKER_CLEANUP_UNKNOWN"),
    ({"streams_complete": False}, "PACKAGE_EXECUTION_CHECKER_STREAM_INCOMPLETE"),
    ({"stdout_overflowed": True}, "PACKAGE_EXECUTION_CHECKER_OUTPUT_CAPACITY"),
    ({"stderr_overflowed": True}, "PACKAGE_EXECUTION_CHECKER_OUTPUT_CAPACITY"),
    ({"returncode": False}, "PACKAGE_EXECUTION_CHECKER_EXIT_STATUS_UNKNOWN"),
    ({"returncode": "0"}, "PACKAGE_EXECUTION_CHECKER_EXIT_STATUS_UNKNOWN"),
    ({"stdout": "not-bytes"}, "PACKAGE_EXECUTION_CHECKER_STREAM_INVALID"),
    ({"stderr": "not-bytes"}, "PACKAGE_EXECUTION_CHECKER_STREAM_INVALID"),
)


@pytest.mark.parametrize(
    "changes,code",
    (
        (
            {"status": _SelectiveEqualitySpoof(owned_process.STATUS_EXITED)},
            "PACKAGE_EXECUTION_CHECKER_STATUS_UNKNOWN",
        ),
        (
            {"cleanup": _SelectiveEqualitySpoof(owned_process.CLEANUP_CONFIRMED)},
            "PACKAGE_EXECUTION_CHECKER_CLEANUP_UNKNOWN",
        ),
    ),
    ids=("spoofed-status-equality", "spoofed-cleanup-equality"),
)
def test_checker_parent_gate_requires_exact_enum_strings(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any], code: str
) -> None:
    def forged(command: list[str], parameters: dict[str, Any], _private: Path) -> Any:
        return _closed_forged_checker_result(command, parameters, **changes)

    monkeypatch.setattr(package_execution, "_run_package_checker", forged)
    with pytest.raises(OSError, match=code):
        package_execution.check_executed(
            emulator_control_execution,
            "CONTROLLER-1.1",
            {"observations": {}, "request": {}},
        )


def test_checker_parent_gate_maps_property_exception_to_typed_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forged(command: list[str], parameters: dict[str, Any], _private: Path) -> Any:
        return _ExplodingStreamsResult(
            _closed_forged_checker_result(command, parameters)
        )

    monkeypatch.setattr(package_execution, "_run_package_checker", forged)
    with pytest.raises(
        OSError, match="PACKAGE_EXECUTION_CHECKER_PROCESS_RESULT_INVALID"
    ):
        package_execution.check_executed(
            emulator_control_execution,
            "CONTROLLER-1.1",
            {"observations": {}, "request": {}},
        )


def test_checker_parent_gate_reads_stream_completeness_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[_CountingStreamsResult] = []

    def forged(command: list[str], parameters: dict[str, Any], _private: Path) -> Any:
        result = _CountingStreamsResult(
            _closed_forged_checker_result(command, parameters)
        )
        observed.append(result)
        return result

    monkeypatch.setattr(package_execution, "_run_package_checker", forged)
    assert package_execution.check_executed(
        emulator_control_execution,
        "CONTROLLER-1.1",
        {"observations": {}, "request": {}},
    ) is True
    assert len(observed) == 1
    assert observed[0].streams_complete_reads == 1


@pytest.mark.parametrize(
    "changes,code",
    _PROCESS_MUTANTS,
    ids=[
        "unknown-status",
        "unknown-cleanup",
        "incomplete-streams",
        "stdout-overflow",
        "stderr-overflow",
        "boolean-returncode",
        "noninteger-returncode",
        "nonbytes-stdout",
        "nonbytes-stderr",
    ],
)
def test_checker_parent_gate_is_positive_and_closed(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any], code: str
) -> None:
    def forged(command: list[str], parameters: dict[str, Any], _private: Path) -> Any:
        return _closed_forged_checker_result(command, parameters, **changes)

    monkeypatch.setattr(package_execution, "_run_package_checker", forged)
    with pytest.raises(OSError, match=code):
        package_execution.check_executed(
            emulator_control_execution,
            "CONTROLLER-1.1",
            {"observations": {}, "request": {}},
        )


def test_checker_parent_gate_accepts_exact_completed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        package_execution,
        "_run_package_checker",
        lambda command, parameters, _private: _closed_forged_checker_result(
            command, parameters
        ),
    )
    assert package_execution.check_executed(
        emulator_control_execution,
        "CONTROLLER-1.1",
        {"observations": {}, "request": {}},
    ) is True


def test_checker_process_uncertainty_maps_to_stable_package_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = NamespaceObject.create("fixture", "OBJECT", {}, {})
    selection = {
        "object_id": item.object_id,
        "mechanism": emulator_control_execution.ADAPTER,
        "reason": "Exercise typed checker infrastructure uncertainty.",
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "a" * 64}],
    }
    route = {
        "coordinate": "CONTROLLER-1.1",
        "obligation_id": "CONTROLLER-1.1-process-boundary",
        "semantic_version": "fixture-1",
        "proposition_digest": "sha256:" + "b" * 64,
        "checking_mechanism": "fixture",
        "reason": "A checker process must complete through the closed boundary.",
    }
    key = item.object_id, emulator_control_execution.ADAPTER
    executed = {"observations": {}, "request": {}, "source_pins": {}}
    monkeypatch.setattr(
        package_execution, "route_mechanism", lambda _route: emulator_control_execution
    )
    monkeypatch.setattr(
        package_execution.observation, "verify_accepted", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(package_execution, "_current_source_pins", lambda: {})

    for changes, code in _PROCESS_MUTANTS:
        monkeypatch.setattr(
            package_execution,
            "_run_package_checker",
            lambda command, parameters, _private, changes=changes:
                _closed_forged_checker_result(command, parameters, **changes),
        )
        snapshot = SimpleNamespace(
            execution_checks={key: selection},
            execution_transports={},
            execution_failures={},
            executions={key: executed},
            collection_digest="sha256:" + "c" * 64,
        )
        result = package_execution.evaluate_selected(snapshot, item, route)
        assert result is not None
        assert result["status"] == "UNKNOWN"
        assert result["reason"] == code


def _detached_replay_case(monkeypatch: pytest.MonkeyPatch, pins: dict[str, str]) -> tuple:
    """One fixture execution whose retained record binds ``pins`` as its source identity."""
    item = NamespaceObject.create("fixture", "OBJECT", {}, {})
    selection = {
        "object_id": item.object_id,
        "mechanism": "fixture-checker-1",
        "reason": "Exercise detached result ownership.",
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "a" * 64}],
    }
    executed = {
        "schema_version": "fixture-observation-1",
        "request": {"nonce": "n"},
        "source_pins": pins,
        "observations": {"nested": [1]},
    }
    module = SimpleNamespace(
        ADAPTER="fixture-checker-1",
        BOUNDARY="Fixture boundary.",
        _execute=lambda snapshot, selected, binding: executed,
    )
    route = {
        "coordinate": "OBJECT-1.1",
        "obligation_id": "OBJECT-1.1-detached-replay",
        "semantic_version": "fixture-1",
        "proposition_digest": "sha256:" + "b" * 64,
        "checking_mechanism": "fixture",
        "reason": "A returned report must not alias retained evidence.",
    }
    snapshot = SimpleNamespace(
        execution_checks={(item.object_id, module.ADAPTER): selection},
        execution_transports={},
        execution_failures={},
        executions={},
        collection_digest="sha256:" + "c" * 64,
    )
    monkeypatch.setattr(package_execution, "route_mechanism", lambda _route: module)
    monkeypatch.setattr(package_execution.observation, "verify_accepted", lambda *args, **kwargs: None)
    monkeypatch.setattr(package_execution, "check_executed", lambda *args: True)
    return item, module, selection, route, snapshot


def test_evaluate_selected_returns_canonical_detached_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The record binds the live tree exactly as execute_bound does; the post-verdict guard checks this equality.
    item, module, selection, route, snapshot = _detached_replay_case(monkeypatch, source_pins())

    result = package_execution.evaluate_selected(snapshot, item, route)
    assert result is not None and result["status"] == "PASS"
    retained = snapshot.executions[(item.object_id, module.ADAPTER)]
    assert result["replay"] == retained and result["replay"] is not retained
    assert result["selection"] == selection and result["selection"] is not selection
    result["replay"]["observations"]["nested"].append(2)
    result["selection"]["reason"] = "changed"
    assert retained["observations"]["nested"] == [1]
    assert selection["reason"] == "Exercise detached result ownership."


def test_evaluate_selected_refuses_stale_source_pins_and_retains_no_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One pinned digest that no longer matches the live bytes is a source change, never a PASS.
    stale = dict(source_pins())
    stale["runtime/package_execution.py"] = "sha256:" + "0" * 64
    item, module, _, route, snapshot = _detached_replay_case(monkeypatch, stale)

    result = package_execution.evaluate_selected(snapshot, item, route)
    assert result is not None and result["status"] == "UNKNOWN"
    assert result["reason"] == "PACKAGE_EXECUTION_SOURCE_CHANGED"
    assert result["replay"] is None and (item.object_id, module.ADAPTER) not in snapshot.executions
    assert snapshot.execution_failures[(item.object_id, module.ADAPTER)]["reason"] == "PACKAGE_EXECUTION_SOURCE_CHANGED"
