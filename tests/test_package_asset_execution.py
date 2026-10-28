"""Source-owned retained-token ASSET checks and fail-closed parent oracle.

Terminology: JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.runtime import package_execution
from verifier.runtime import token_asset_execution as execution
from verifier.runtime import local_ledger_worker
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


NAMES = {
    "ASSET-1.1-capability-identity-units-and-precision",
    "ASSET-2.1-issuance-lifecycle-and-redemption-boundary",
    "ASSET-3.1-capability-encumbrance-and-reconciliation",
}


def test_asset_catalog_is_exact_reasoned_and_source_bound() -> None:
    routes = execution.catalog()
    assert {row["obligation_id"] for row in routes} == NAMES
    assert [row["tier"] for row in routes] == [1, 2, 3]
    assert all(
        row["object_kind"] == "ASSET"
        and row["adapter"] == "verifier-token-asset-1"
        and row["reason"].strip()
        and row["exact_claim"].strip()
        for row in routes
    )
    assert execution.IMPLEMENTATION == "src/verifier/domains/contracts/token_checks.py"


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {
        "schema_version": execution.REQUEST_SCHEMA,
        "nonce": "token-asset-control-regression",
        "object_id": "vstd-token",
        "object_digest": "sha256:" + "1" * 64,
        "collection_digest": "sha256:" + "2" * 64,
    }
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B",
         str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode("utf-8"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stderr == b""
    assert len(result.stdout) < 1024 * 1024
    report = json.loads(result.stdout)
    assert report["request"] == request
    assert report["source_pins"] == source_pins()
    return report["observations"]


@pytest.mark.parametrize("coordinate", [row["coordinate"] for row in execution.catalog()])
def test_actual_token_asset_execution_satisfies_finite_claim(
    observations: dict[str, Any], coordinate: str
) -> None:
    assert execution.check_observations(coordinate, observations)


@pytest.mark.parametrize(
    "coordinate,path,replacement",
    [
        ("ASSET-1.1", ("declaration", "window_unit"), "second"),
        ("ASSET-1.1", ("checks", "windows", "reported_result", "status"), "UNKNOWN"),
        ("ASSET-1.1", ("controls", "boolean_integer", "reported_result", "status"), "PASS"),
        ("ASSET-1.1", ("controls", "unadmitted_unit", "reported_result", "status"), "PASS"),
        ("ASSET-2.1", ("boundary", "redemption"), "PASS"),
        ("ASSET-2.1", ("checks", "tenure", "reported_result", "authority"), "PASS"),
        ("ASSET-2.1", ("controls", "revival", "reported_result", "status"), "PASS"),
        ("ASSET-2.1", ("controls", "unsupported_asset", "reported_result", "status"), "PASS"),
        ("ASSET-3.1", ("boundary", "real_custody"), "PASS"),
        ("ASSET-3.1", ("boundary", "supply_conservation"), "PASS"),
        ("ASSET-3.1", ("checks", "delegation", "reported_result", "status"), "FAIL"),
        ("ASSET-3.1", ("controls", "widened_scope", "reported_result", "status"), "PASS"),
    ],
)
def test_parent_oracle_refuses_status_and_boundary_forgery(
    observations: dict[str, Any], coordinate: str, path: tuple[Any, ...], replacement: Any
) -> None:
    changed = deepcopy(observations)
    row: Any = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    with pytest.raises(ValueError, match="TOKEN_ASSET_"):
        execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate,check", [
    ("ASSET-1.1", "windows"),
    ("ASSET-2.1", "tenure"),
    ("ASSET-3.1", "delegation"),
])
def test_certificate_mutation_and_cross_objective_selection_refuse(
    observations: dict[str, Any], coordinate: str, check: str
) -> None:
    changed = deepcopy(observations)
    encoded = changed["checks"][check]["certificate"]
    raw = bytearray(base64.b64decode(encoded))
    raw[len(raw) // 2] ^= 1
    changed["checks"][check]["certificate"] = base64.b64encode(raw).decode("ascii")
    with pytest.raises(ValueError):
        execution.check_observations(coordinate, changed)

    changed = deepcopy(observations)
    other = {"windows": "tenure", "tenure": "delegation", "delegation": "windows"}[check]
    changed["checks"][check]["request"] = deepcopy(
        observations["checks"][other]["request"]
    )
    with pytest.raises(ValueError):
        execution.check_observations(coordinate, changed)


def test_wrong_route_is_never_accepted(observations: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_COORDINATE_UNREGISTERED"):
        execution.check_observations("ASSET-9.9", observations)


def _launch_record(pins: dict[str, str], observations: dict[str, Any]) -> dict[str, Any]:
    """One accepted worker report, shaped as ``execute_bound`` returns it."""
    return {"schema_version": execution.OBSERVATION_SCHEMA, "request": {"nonce": "cache-control"},
        "source_pins": pins, "observations": observations}


def _cache_snapshot(item: NamespaceObject) -> SimpleNamespace:
    selection = {
        "object_id": item.object_id,
        "mechanism": execution.ADAPTER,
        "reason": "Exercise the exact owned token checker.",
        "evidence": [],
    }
    return SimpleNamespace(
        execution_checks={(item.object_id, execution.ADAPTER): selection},
        executions={}, execution_failures={}, execution_transports={},
        collection_digest="sha256:" + "3" * 64,
    )


def _stub_launch(monkeypatch: pytest.MonkeyPatch, observations: dict[str, Any],
                 reorder: bool = False) -> SimpleNamespace:
    """Replace the launch and the live pin read, both captured once for the whole test.

    The shared source tree can change while a test runs, so reading ``source_pins()``
    at each comparison would make cache tests depend on concurrent writes. One frozen
    snapshot keeps both sides of the cache comparison exact and reproducible.
    """
    current = source_pins()
    launched = dict(reversed(list(current.items()))) if reorder else current
    calls: list[int] = []

    def run_once(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(1)
        return _launch_record(launched, observations)

    monkeypatch.setattr(execution, "_execute", run_once)
    monkeypatch.setattr(package_execution, "route_mechanism", lambda route: execution)
    monkeypatch.setattr(package_execution, "_current_source_pins", lambda: current)
    monkeypatch.setattr(package_execution.observation, "verify_accepted", lambda *args, **kwargs: None)
    return SimpleNamespace(calls=calls, pins=current)


def _evaluate_all_routes(snapshot: Any, item: NamespaceObject) -> list[dict[str, Any] | None]:
    return [execution.evaluate(snapshot, item, route) for route in execution.catalog()]


def test_one_source_bound_launch_is_cached_across_all_asset_routes(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    item = NamespaceObject.create("asset", "OBJECT", {}, {})
    stub = _stub_launch(monkeypatch, observations)
    results = _evaluate_all_routes(_cache_snapshot(item), item)
    assert stub.calls == [1]
    assert all(result is not None and result["status"] == "PASS" for result in results)


def test_reordered_equivalent_pins_are_the_same_binding(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = _stub_launch(monkeypatch, observations, reorder=True)
    reordered = dict(reversed(list(stub.pins.items())))
    assert list(reordered) != list(stub.pins)
    # Canonical JSON sorts keys, so the digest that names a launch ignores insertion order.
    assert value_digest(reordered) == value_digest(stub.pins)
    item = NamespaceObject.create("asset", "OBJECT", {}, {})
    results = _evaluate_all_routes(_cache_snapshot(item), item)
    assert stub.calls == [1]
    assert all(result is not None and result["status"] == "PASS" for result in results)


def test_cached_launch_without_source_pins_is_not_reused(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    item = NamespaceObject.create("asset", "OBJECT", {}, {})
    key = (item.object_id, execution.ADAPTER)
    snapshot = _cache_snapshot(item)
    snapshot.executions[key] = {"observations": observations}
    stub = _stub_launch(monkeypatch, observations)
    results = _evaluate_all_routes(snapshot, item)
    assert stub.calls == [1]
    assert all(result is not None and result["status"] == "PASS" for result in results)
    assert snapshot.executions[key]["source_pins"] == stub.pins


@pytest.mark.parametrize(
    "pin",
    ["runtime/token_asset_worker.py", "domains/contracts/token_checks.py"],
    ids=["one-changed-worker-pin", "stale-mechanism-implementation-pin"],
)
def test_cached_launch_with_one_stale_pin_relaunches_once(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch, pin: str
) -> None:
    stub = _stub_launch(monkeypatch, observations)
    assert pin in stub.pins
    stale = {**stub.pins, pin: "sha256:" + "0" * 64}
    item = NamespaceObject.create("asset", "OBJECT", {}, {})
    key = (item.object_id, execution.ADAPTER)
    snapshot = _cache_snapshot(item)
    snapshot.executions[key] = _launch_record(stale, observations)
    results = _evaluate_all_routes(snapshot, item)
    assert stub.calls == [1]
    assert all(result is not None and result["status"] == "PASS" for result in results)
    assert snapshot.executions[key]["source_pins"] == stub.pins


def test_fresh_launch_without_source_pins_fails_closed_and_is_not_cached(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real ``execute_bound``: a report that omits pins is unavailable and never cached."""
    monkeypatch.setattr(local_ledger_worker, "source_pins", lambda: {"runtime/alpha.py": "sha256:" + "1" * 64})
    item = NamespaceObject.create("asset", "OBJECT", {}, {})
    key = (item.object_id, execution.ADAPTER)
    selection = {
        "object_id": item.object_id,
        "mechanism": execution.ADAPTER,
        "reason": "Exercise the exact owned token checker.",
        "evidence": [{"path": execution.IMPLEMENTATION, "sha256": "sha256:" + "a" * 64}],
    }
    snapshot = SimpleNamespace(
        rows={item.object_id: {"surfaces": ["file:" + execution.IMPLEMENTATION]}},
        root=Path(__file__).resolve().parents[1], read=lambda ref: b"",
        collection_digest="sha256:" + "3" * 64,
        execution_checks={key: selection},
        executions={}, execution_failures={}, execution_transports={},
    )
    sent: list[int] = []

    def run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        sent.append(1)
        report = {"schema_version": execution.OBSERVATION_SCHEMA,
            "request": strict_json_loads(kwargs["input"].decode("utf-8")), "observations": observations}
        return SimpleNamespace(returncode=0, stdout=canonical_bytes(report) + b"\n", stderr=b"")

    monkeypatch.setattr(package_execution.subprocess, "run", run)
    results = _evaluate_all_routes(snapshot, item)
    assert sent == [1]
    assert all(result is not None and result["status"] == "UNKNOWN" for result in results)
    assert {result["reason"] for result in results if result} == {"PACKAGE_EXECUTION_SOURCE_PINS_INVALID"}
    assert key not in snapshot.executions
    assert snapshot.execution_transports[key]["outcome"] == "REJECTED"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": "wrong", "nonce": "x", "object_id": "x",
         "object_digest": "x", "collection_digest": "x"},
        {"schema_version": execution.REQUEST_SCHEMA, "nonce": True, "object_id": "x",
         "object_digest": "x", "collection_digest": "x"},
        {"schema_version": execution.REQUEST_SCHEMA, "nonce": "x", "object_id": "x",
         "object_digest": "x", "collection_digest": "x", "command": "arbitrary"},
    ],
)
def test_worker_request_is_closed_and_contains_no_command(payload: dict[str, Any]) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B",
         str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == b""


def test_claim_boundary_retains_every_unestablished_consequence(
    observations: dict[str, Any]
) -> None:
    assert observations["boundary"] == {
        "issuer_authority": "NOT_ESTABLISHED",
        "signature_validity": "NOT_ESTABLISHED",
        "real_custody": "NOT_ESTABLISHED",
        "holding_completeness": "NOT_ESTABLISHED",
        "redemption": "NOT_ESTABLISHED",
        "application_enforcement": "NOT_ESTABLISHED",
        "supply_conservation": "NOT_ESTABLISHED",
        "backing": "NOT_ESTABLISHED",
    }

