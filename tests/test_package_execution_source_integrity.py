"""Source-integrity classification at the package obligation result layer.

Each row runs the production ``evaluate_selected`` route with the worker launch
replaced by a recording substitute, so the observed obligation status and closed
reason are what a package report would receive. The source tree is a mutable fake,
which places drift before, during and after one launch. The checker is substituted
only for the accepted path, so every refusal row is produced by production code.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.runtime import emulator_control_execution as emulator
from verifier.runtime import local_ledger_execution as ledger
from verifier.runtime import local_ledger_worker
from verifier.runtime import manifest_write_execution as manifest
from verifier.runtime import package_execution
from verifier.runtime.tier_zero_profile import canonical_bytes


ROOT = Path(__file__).resolve().parents[1]
MODULES = (ledger, manifest, emulator)
PINS = {"runtime/alpha.py": "sha256:" + "1" * 64, "runtime/beta.py": "sha256:" + "2" * 64}
MOVED = {**PINS, "runtime/alpha.py": "sha256:" + "3" * 64}
OTHER = {**PINS, "runtime/beta.py": "sha256:" + "4" * 64}
ALPHA_PATH = "src/verifier/runtime/alpha.py"

UNKNOWN, FAIL, PASS = "UNKNOWN", "FAIL", "PASS"
SOURCE_CHANGED = "PACKAGE_EXECUTION_SOURCE_CHANGED"
PINS_INVALID = "PACKAGE_EXECUTION_SOURCE_PINS_INVALID"
PINS_CONTRADICTED = "PACKAGE_EXECUTION_SOURCE_PINS_CONTRADICTED"
REPLY_MALFORMED = "PACKAGE_EXECUTION_REPLY_MALFORMED"
REPLY_ENCODING = "PACKAGE_EXECUTION_REPLY_ENCODING_INVALID"
REQUEST_DIFFERS = "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS"
EVIDENCE_DIFFERS = "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS"


@pytest.fixture
def tree(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"pins": dict(PINS)}
    monkeypatch.setattr(local_ledger_worker, "source_pins", lambda: dict(state["pins"]))
    monkeypatch.setattr(package_execution, "check_executed", lambda module, coordinate, executed: True)
    return state


def _snapshot(module: Any, read: Callable[[dict[str, str]], bytes]) -> tuple[SimpleNamespace, NamespaceObject]:
    item = NamespaceObject.create("subject", "OBJECT", {}, {})
    selection = {"object_id": item.object_id, "mechanism": module.ADAPTER,
        "reason": "Source-integrity control for one package obligation.",
        "evidence": [{"path": module.IMPLEMENTATION, "sha256": "sha256:" + "a" * 64}]}
    snapshot = SimpleNamespace(root=ROOT, collection_digest="sha256:" + "b" * 64, read=read,
        rows={item.object_id: {"surfaces": ["file:" + module.IMPLEMENTATION]}},
        execution_checks={(item.object_id, module.ADAPTER): selection},
        executions={}, execution_failures={}, execution_transports={})
    return snapshot, item


def _quiet_read(ref: dict[str, str]) -> bytes:
    return b""


def _failing_read(path: str, error: Exception) -> Callable[[dict[str, str]], bytes]:
    def read(ref: dict[str, str]) -> bytes:
        if ref["path"] == path:
            raise error
        return b""
    return read


def _install_worker(monkeypatch: pytest.MonkeyPatch, module: Any, tree: dict[str, Any],
                    reply: Callable[[Any, dict[str, Any], dict[str, str]], bytes],
                    after: Callable[[dict[str, Any], int], None] | None = None) -> list[dict[str, Any]]:
    """Record every launch; ``reply`` sees the pins the child reads, ``after`` moves the tree."""
    launches: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        request = strict_json_loads(kwargs["input"].decode("utf-8"))
        launches.append(request)
        raw = reply(module, request, dict(tree["pins"]))
        if after is not None:
            after(tree, len(launches))
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    monkeypatch.setattr(package_execution.subprocess, "run", run)
    return launches


def _report(module: Any, request: dict[str, Any], pins: dict[str, str]) -> dict[str, Any]:
    return {"schema_version": module.OBSERVATION_SCHEMA, "request": request,
            "source_pins": pins, "observations": {"fact": 1}}


def _edit(change: Callable[[dict[str, Any]], None]) -> Callable[[Any, dict[str, Any], dict[str, str]], bytes]:
    """An otherwise exact request-bound reply, altered only by ``change``."""
    def reply(module: Any, request: dict[str, Any], pins: dict[str, str]) -> bytes:
        body = _report(module, request, pins)
        change(body)
        return canonical_bytes(body) + b"\n"
    return reply


def _raw(payload: bytes) -> Callable[[Any, dict[str, Any], dict[str, str]], bytes]:
    return lambda module, request, pins: payload


def _reorder(body: dict[str, Any]) -> None:
    body["source_pins"] = dict(reversed(list(body["source_pins"].items())))


def _set_pin(body: dict[str, Any]) -> None:
    body["source_pins"]["runtime/alpha.py"] = "sha256:" + "6" * 64


MATRIX: dict[str, dict[str, Any]] = {
    # Missing or malformed source_pins is an unavailable obligation, never a semantic refutation.
    "absent": dict(reply=_edit(lambda b: b.pop("source_pins")), status=UNKNOWN, reason=PINS_INVALID,
                   outcome="REJECTED", launches=1),
    "wrong-type": dict(reply=_edit(lambda b: b.__setitem__("source_pins", ["not", "a", "map"])),
                       status=UNKNOWN, reason=PINS_INVALID, outcome="REJECTED", launches=1),
    "malformed-digest": dict(reply=_edit(lambda b: b["source_pins"].__setitem__("runtime/alpha.py", "sha256:xyz")),
                             status=UNKNOWN, reason=PINS_INVALID, outcome="REJECTED", launches=1),
    # A shape-valid map that disagrees with a stable tree is a child contradiction.
    "missing-entry": dict(reply=_edit(lambda b: b["source_pins"].pop("runtime/alpha.py")),
                          status=FAIL, reason=PINS_CONTRADICTED, outcome="REJECTED", launches=1),
    "extra-entry": dict(reply=_edit(lambda b: b["source_pins"].__setitem__("runtime/gamma.py", "sha256:" + "5" * 64)),
                        status=FAIL, reason=PINS_CONTRADICTED, outcome="REJECTED", launches=1),
    "altered-digest": dict(reply=_edit(_set_pin), status=FAIL, reason=PINS_CONTRADICTED,
                           outcome="REJECTED", launches=1),
    "reordered-equivalent": dict(reply=_edit(_reorder), status=PASS, reason="BOUNDARY",
                                 outcome="ACCEPTED", launches=1),
    # Reply faults keep their transport outcome and receive closed obligation codes.
    "non-json": dict(reply=_raw(b"{bad"), status=UNKNOWN, reason=REPLY_MALFORMED,
                     outcome="REJECTED", launches=1),
    "duplicate-key": dict(reply=_raw(b'{"schema_version":"x","schema_version":"y"}'), status=UNKNOWN,
                          reason=REPLY_MALFORMED, outcome="REJECTED", launches=1),
    "invalid-utf8": dict(reply=_raw(b"\xff"), status=UNKNOWN, reason=REPLY_ENCODING,
                         outcome="REJECTED", launches=1),
    # Parseable but contradictory bindings with a stable tree remain semantic refusals.
    "envelope-extra": dict(reply=_edit(lambda b: b.__setitem__("extra", True)), status=FAIL,
                           reason=REQUEST_DIFFERS, outcome="REJECTED", launches=1),
    "request-mismatch": dict(reply=_edit(lambda b: b["request"].__setitem__("nonce", "0" * 64)),
                             status=FAIL, reason=REQUEST_DIFFERS, outcome="REJECTED", launches=1),
    # Tree movement dominates: a contradiction under a moving tree is not stable evidence.
    "postlaunch-moved": dict(reply=_edit(lambda b: None),
                             after=lambda state, count: state.update(pins=dict(MOVED)),
                             status=UNKNOWN, reason=SOURCE_CHANGED, outcome="REJECTED", launches=1),
    "postlaunch-moved-and-contradicting": dict(reply=_edit(_set_pin),
                                               after=lambda state, count: state.update(pins=dict(MOVED)),
                                               status=UNKNOWN, reason=SOURCE_CHANGED,
                                               outcome="REJECTED", launches=1),
    # Pin capture that fails before launch is pin-capture drift, not evidence staleness.
    "prelaunch-pin-drift": dict(reply=_edit(lambda b: None),
                                read=lambda module: _failing_read(
                                    ALPHA_PATH, ValueError(EVIDENCE_DIFFERS)),
                                status=UNKNOWN, reason=SOURCE_CHANGED, outcome=None, launches=0),
    "prelaunch-pin-unreadable": dict(reply=_edit(lambda b: None),
                                     read=lambda module: _failing_read(ALPHA_PATH, OSError("unreadable")),
                                     status=UNKNOWN, reason=SOURCE_CHANGED, outcome=None, launches=0),
    # A resource limit during pin capture keeps its own typed reason; it is not drift.
    "prelaunch-pin-capacity": dict(reply=_edit(lambda b: None),
                                   read=lambda module: _failing_read(
                                       ALPHA_PATH, OSError("PACKAGE_INSTANCE_EVIDENCE_CAPACITY")),
                                   status=UNKNOWN, reason="PACKAGE_INSTANCE_EVIDENCE_CAPACITY",
                                   outcome=None, launches=0),
    # A malformed pin path is unavailable source-pin evidence, not a digest drift.
    "prelaunch-pin-malformed-path": dict(reply=_edit(lambda b: None),
                                         read=lambda module: _failing_read(
                                             ALPHA_PATH, ValueError("PACKAGE_INSTANCE_PATH_ESCAPES_ROOT")),
                                         status=UNKNOWN, reason=PINS_INVALID, outcome=None, launches=0),
    # Selected instance evidence that no longer matches its digest remains a semantic FAIL.
    "evidence-stale": dict(reply=_edit(lambda b: None),
                           read=lambda module: _failing_read(module.IMPLEMENTATION, ValueError(EVIDENCE_DIFFERS)),
                           status=FAIL, reason=EVIDENCE_DIFFERS, outcome=None, launches=0),
}


def _evaluate(module: Any, snapshot: SimpleNamespace, item: NamespaceObject) -> dict[str, Any]:
    result = package_execution.evaluate_selected(snapshot, item, module.catalog()[0])
    assert result is not None
    return result


@pytest.mark.parametrize("case", sorted(MATRIX))
@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
def test_obligation_result_classifies_source_integrity(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any, case: str
) -> None:
    spec = MATRIX[case]
    launches = _install_worker(monkeypatch, module, tree, spec["reply"], spec.get("after"))
    read = spec["read"](module) if "read" in spec else _quiet_read
    snapshot, item = _snapshot(module, read)
    result = _evaluate(module, snapshot, item)
    expected_reason = module.BOUNDARY if spec["reason"] == "BOUNDARY" else spec["reason"]
    assert (result["status"], result["reason"]) == (spec["status"], expected_reason), result
    assert len(launches) == spec["launches"]
    transport = snapshot.execution_transports.get((item.object_id, module.ADAPTER))
    assert (transport["outcome"] if transport is not None else None) == spec["outcome"]
    if spec["status"] == PASS:
        assert result["replay"] is not None and result["applicability_established"] is True
    else:
        assert result["replay"] is None and result["applicability_established"] is False


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
@pytest.mark.parametrize("raw,exception", [
    (b"{bad", "JSONDecodeError"),
    (b'{"schema_version":"x","schema_version":"y"}', "StrictJsonError"),
    (b"\xff", "UnicodeDecodeError"),
], ids=["non-json", "duplicate-key", "invalid-utf8"])
def test_reply_parse_faults_keep_protocol_visible_exception_types(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any, raw: bytes, exception: str
) -> None:
    """The protocol oracle reads exception type names from ``execute_bound``; those stay exact."""
    _install_worker(monkeypatch, module, tree, _raw(raw))
    snapshot, item = _snapshot(module, _quiet_read)
    selection = snapshot.execution_checks[(item.object_id, module.ADAPTER)]
    with pytest.raises(Exception) as raised:
        package_execution.execute_bound(snapshot, item, selection)
    assert type(raised.value).__name__ == exception


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
def test_stable_contradiction_keeps_protocol_visible_exception_text(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    """Protocol PROTOCOL-3.1 reads ``ValueError`` text; the obligation code is separate."""
    _install_worker(monkeypatch, module, tree, _edit(_set_pin))
    snapshot, item = _snapshot(module, _quiet_read)
    selection = snapshot.execution_checks[(item.object_id, module.ADAPTER)]
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_SOURCE_CHANGED$"):
        package_execution.execute_bound(snapshot, item, selection)


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
def test_stale_cached_receipt_relaunches_exactly_once_and_binds_current_pins(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    launches = _install_worker(monkeypatch, module, tree, _edit(lambda b: None))
    snapshot, item = _snapshot(module, _quiet_read)
    first = _evaluate(module, snapshot, item)
    assert (first["status"], first["reason"]) == (PASS, module.BOUNDARY), first
    tree["pins"] = dict(MOVED)
    second = _evaluate(module, snapshot, item)
    assert (second["status"], second["reason"]) == (PASS, module.BOUNDARY), second
    assert len(launches) == 2, "exactly one relaunch for one stale cached receipt"
    assert snapshot.executions[(item.object_id, module.ADAPTER)]["source_pins"] == MOVED


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
def test_stale_cached_relaunch_moved_again_is_unknown_and_never_relaunched(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    def move_during_relaunch(state: dict[str, Any], count: int) -> None:
        if count == 2:
            state["pins"] = dict(OTHER)

    launches = _install_worker(monkeypatch, module, tree, _edit(lambda b: None), move_during_relaunch)
    snapshot, item = _snapshot(module, _quiet_read)
    assert _evaluate(module, snapshot, item)["status"] == PASS
    tree["pins"] = dict(MOVED)
    second = _evaluate(module, snapshot, item)
    assert (second["status"], second["reason"]) == (UNKNOWN, SOURCE_CHANGED), second
    third = _evaluate(module, snapshot, item)
    assert (third["status"], third["reason"]) == (UNKNOWN, SOURCE_CHANGED), third
    assert len(launches) == 2, "The coordinate moved during the one relaunch; no further launch is made."


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.ADAPTER)
def test_post_verdict_source_drift_is_unknown_and_retains_no_pass(
    tree: dict[str, Any], monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    def drift_after_checker(checked: Any, coordinate: str, executed: dict[str, Any]) -> bool:
        tree["pins"] = dict(MOVED)
        return True

    monkeypatch.setattr(package_execution, "check_executed", drift_after_checker)
    launches = _install_worker(monkeypatch, module, tree, _edit(lambda b: None))
    snapshot, item = _snapshot(module, _quiet_read)
    key = (item.object_id, module.ADAPTER)
    result = _evaluate(module, snapshot, item)
    assert (result["status"], result["reason"]) == (UNKNOWN, SOURCE_CHANGED), result
    assert result["replay"] is None and result["applicability_established"] is False
    assert key not in snapshot.executions, "A PASS-producing exchange must not stay cached."
    assert snapshot.execution_failures[key] == {"status": UNKNOWN, "reason": SOURCE_CHANGED}
    again = _evaluate(module, snapshot, item)
    assert (again["status"], again["reason"]) == (UNKNOWN, SOURCE_CHANGED)
    assert len(launches) == 1, "Post-verdict drift never authorizes a relaunch."
