"""Source-bound worker protocol checks for Verifier Standard (VSTD)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from test_package_polish import declared_package
from test_package_ledger_execution import select_execution as ledger_selection
from test_package_kind_requirements import save
from verifier.runtime import package_polish as package, worker_protocol_execution as execution
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.manifest_gate import obligation_catalog, assess_object_gate
from verifier.runtime.package_execution_observation import OUTPUT_LIMIT


NAMES = {
    "PROTOCOL-1.1-fixed-worker-selection", "PROTOCOL-1.2-response-envelope",
    "PROTOCOL-2.1-fresh-exchange", "PROTOCOL-2.2-failure-without-retry",
    "PROTOCOL-3.1-executable-source-binding", "PROTOCOL-3.2-response-capacity",
}


def test_worker_protocol_has_reasoned_executable_routes() -> None:
    routes = {row["obligation_id"]: row for row in obligation_catalog()}
    assert NAMES <= routes.keys()
    assert all(routes[name]["reason"].strip() and routes[name]["exact_claim"].strip() for name in NAMES)


def test_worker_protocol_outer_timeout_is_closed_and_compositional() -> None:
    from types import SimpleNamespace
    from verifier.runtime import package_execution, package_execution_observation

    assert execution.WORKER_TIMEOUT_SECONDS == 90
    assert package_execution._worker_timeout_seconds(execution) == 90
    assert package_execution_observation.worker_timeout_seconds(execution) == 90
    assert package_execution._worker_timeout_seconds(SimpleNamespace()) == 30
    assert package_execution_observation.worker_timeout_seconds(SimpleNamespace()) == 30
    for invalid in (True, 0, 91, 30.0, "90"):
        with pytest.raises(
            ValueError, match="PACKAGE_EXECUTION_WORKER_TIMEOUT_DECLARATION_INVALID"
        ):
            package_execution._worker_timeout_seconds(
                SimpleNamespace(WORKER_TIMEOUT_SECONDS=invalid)
            )
        with pytest.raises(
            ValueError, match="PACKAGE_EXECUTION_WORKER_TIMEOUT_DECLARATION_INVALID"
        ):
            package_execution_observation.worker_timeout_seconds(
                SimpleNamespace(WORKER_TIMEOUT_SECONDS=invalid)
            )


def test_protocol_admission_route_names_participants_roles_states_and_transitions() -> None:
    route = next(row for row in execution.catalog() if row["coordinate"] == "PROTOCOL-1.1")
    text = (route["reason"] + " " + route["exact_claim"]).lower()
    assert all(term in text for term in ("participant", "role", "state", "transition"))


def _run_worker() -> tuple[dict[str, Any], bytes]:
    """Run the real observation worker once and return its request and exact stdout bytes."""
    request = {"schema_version": execution.REQUEST_SCHEMA, "nonce": "protocol-control-regression",
        "object_id": "protocol", "object_digest": "sha256:" + "1" * 64, "collection_digest": "sha256:" + "2" * 64}
    result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode(), capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode()
    return request, result.stdout


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request, stdout = _run_worker()
    report = json.loads(stdout)
    assert report["request"] == request and report["source_pins"] == source_pins()
    return report["observations"]


def test_worker_observation_fits_the_parent_capture_bound() -> None:
    """The observation is itself one package-instance reply, so the parent's capture bound must admit it."""
    _, stdout = _run_worker()
    assert len(stdout) <= OUTPUT_LIMIT, f"observation is {len(stdout)} bytes; the parent accepts {OUTPUT_LIMIT}"


def test_fault_rows_keep_outcome_digest_and_capacity_boundary_not_bytes(observations: dict[str, Any]) -> None:
    """Fault parents keep digests, lengths and truncation; real exchanges keep their complete retained streams."""
    for name, row in observations["faults"].items():
        parent = row["parent_record"]
        if parent is None:
            continue
        assert parent["retained_streams"] == "OMITTED_OUTER_CHANNEL_BOUND", name
        assert parent["full_observation_digest"].startswith("sha256:"), name
        assert all(parent[stream] is None or "retained_base64" not in parent[stream] for stream in ("stdin", "stdout", "stderr")), name
    at_capacity, over_capacity = observations["faults"]["at_capacity"]["parent_record"], observations["faults"]["over_capacity"]["parent_record"]
    assert (at_capacity["stdout"]["bytes"], at_capacity["stdout"]["truncated"]) == (1048576, False)
    assert (over_capacity["stdout"]["bytes"], over_capacity["stdout"]["truncated"]) == (1048577, True)
    assert all("retained_base64" in row["parent_record"]["stdout"] for row in observations["real"])


@pytest.mark.parametrize("coordinate", ["PROTOCOL-1.1", "PROTOCOL-1.2", "PROTOCOL-2.1", "PROTOCOL-2.2", "PROTOCOL-3.1", "PROTOCOL-3.2"])
def test_actual_protocol_execution_satisfies_finite_claim(observations: dict[str, Any], coordinate: str) -> None:
    assert all("TMPDIR" in row["environment_keys"] for row in observations["real"])
    assert execution.check_observations(coordinate, observations), observations


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("PROTOCOL-1.1", ("real", 0, "worker"), "caller-worker.py"),
    ("PROTOCOL-1.1", ("real", 0, "flags"), ["-B"]),
    ("PROTOCOL-1.1", ("real", 0, "environment_keys"), ["PYTHONPATH"]),
    ("PROTOCOL-1.1", ("real", 0, "environment_keys"), ["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"]),
    ("PROTOCOL-1.1", ("real", 0, "parameters", "capture_output"), 1),
    ("PROTOCOL-1.2", ("faults", "duplicate", "returned"), True),
    ("PROTOCOL-1.2", ("faults", "extra", "exception"), "OSError"),
    ("PROTOCOL-2.1", ("real", 0, "request", "nonce"), "weak"),
    ("PROTOCOL-2.1", ("faults", "nonce", "returned"), True),
    ("PROTOCOL-2.2", ("faults", "timeout", "calls"), 2),
    ("PROTOCOL-2.2", ("faults", "exit", "calls"), True),
    ("PROTOCOL-3.1", ("faults", "selected_source", "calls"), 1),
    ("PROTOCOL-3.1", ("faults", "recapture", "returned"), True),
    ("PROTOCOL-3.2", ("faults", "at_capacity", "response_bytes"), 1048575),
    ("PROTOCOL-3.2", ("faults", "at_capacity", "response_bytes"), 1048577),
    ("PROTOCOL-3.2", ("faults", "over_capacity", "response_bytes"), 1048576),
    ("PROTOCOL-3.2", ("faults", "over_capacity", "returned"), True),
    ("PROTOCOL-3.2", ("faults", "over_capacity", "parent_record", "outcome"), "REJECTED"),
])
def test_protocol_oracle_refuses_wrong_binding_or_outcome(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    # A refusal proves nothing unless the unmodified observation is accepted for the same coordinate.
    assert execution.check_observations(coordinate, observations), "mutation base must be accepted"
    changed = deepcopy(observations)
    row = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("guard,coordinates", [
    ("PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS", ("PROTOCOL-1.2", "PROTOCOL-2.1")),
    ("PACKAGE_EXECUTION_SOURCE_CHANGED", ("PROTOCOL-3.1",)),
    ("PACKAGE_EXECUTION_OUTPUT_CAPACITY", ("PROTOCOL-3.2",)),
])
def test_disabled_production_guard_is_detected(monkeypatch: pytest.MonkeyPatch, guard: str,
        coordinates: tuple[str, ...]) -> None:
    from verifier.core import owned_process
    from verifier.runtime import package_execution, package_instance_evidence, worker_protocol_worker
    if guard == "PACKAGE_EXECUTION_OUTPUT_CAPACITY":
        # The capacity classification is a direct raise at the transport seam, not a _require call.
        # Disable only its overflow flag, so an oversize reply is handed on as if it were complete.
        def overflow_unclassified(command: list[str], child_parameters: dict[str, Any], _private: Any) -> Any:
            completed = subprocess.run(command, **child_parameters)
            return owned_process.OwnedProcessResult(status=owned_process.STATUS_EXITED,
                cleanup=owned_process.CLEANUP_CONFIRMED, returncode=completed.returncode,
                stdout=completed.stdout, stderr=completed.stderr, stdout_overflowed=False, stderr_overflowed=False)

        monkeypatch.setattr(package_execution, "_run_package_worker", overflow_unclassified)
    else:
        original = package_instance_evidence._require

        def weakened(condition: bool, code: str) -> None:
            if code != guard:
                original(condition, code)

        monkeypatch.setattr(package_instance_evidence, "_require", weakened)
    mutated = worker_protocol_worker.observe()
    assert all(not execution.check_observations(coordinate, mutated) for coordinate in coordinates)


def test_added_transport_retry_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import package_execution, worker_protocol_worker
    original = package_execution.execute_bound

    def retry(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return original(*args, **kwargs)
        except subprocess.TimeoutExpired:
            return original(*args, **kwargs)

    monkeypatch.setattr(package_execution, "execute_bound", retry)
    assert not execution.check_observations("PROTOCOL-2.2", worker_protocol_worker.observe())


def test_participant_state_route_rejects_replayed_exchange_as_second_participant_step() -> None:
    """PROTOCOL-0.1 needs distinct state-machine transitions, not two aliases."""
    request = {
        "schema_version": "verifier-local-ledger-execution-request-1",
        "nonce": "a" * 64,
        "object_id": "protocol-peer",
        "object_digest": "sha256:" + "1" * 64,
        "collection_digest": "sha256:" + "2" * 64,
    }
    exchange = {
        "worker": "local_ledger_worker.py",
        "flags": ["-I", "-S", "-B"],
        "interpreter_matches": True,
        "request": request,
        "reply_request": deepcopy(request),
        "environment_keys": ["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH"],
        "parameters": {"capture_output": True, "timeout": 30, "check": False},
    }
    observed = {"real": [exchange, deepcopy(exchange)], "faults": {}}
    assert not execution.check_observations("PROTOCOL-1.1", observed)


def test_actual_protocol_check_reaches_package_and_focused_gate(declared_package: tuple) -> None:
    root, retained, _ = declared_package
    document = ledger_selection(root, retained)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row["specializations"].append("PROTOCOL")
    row["surfaces"].append("file:" + execution.IMPLEMENTATION)
    document["namespace"]["execution_checks"].append({"object_id": "external", "mechanism": execution.ADAPTER,
        "reason": "This object owns the exact dispatcher as well as its ledger; separate role evidence is required.",
        "evidence": [{"path": execution.IMPLEMENTATION,
            "sha256": package.binding.bytes_digest((root / execution.IMPLEMENTATION).read_bytes())}]})
    save(root, document)
    report = package.assess_package_polish(3, root)
    rows = [row for row in report["obligation_instances"] if row["object_id"] == "external" and row["object_kind"] == "PROTOCOL"]
    assert len(rows) == 6 and all(row["status"] == "PASS" for row in rows), report["blockers"]
    contract = next(row for row in report["kind_requirements"]["contract_coverage"]["contracts"]
                    if row["object_id"] == "external" and row["kind"] == "PROTOCOL")
    assert contract["finite_check_status"] == "PASS" and len(contract["clauses"]) == 6
    assert all(row["result_digest"] == package.binding.value_digest(instance)
               for row, instance in zip(contract["clauses"], rows))
    assert contract["status"] == "UNKNOWN" and contract["residual_requirements"]
    assert report["status"] == "UNKNOWN" and not report["polished"]
    gate = assess_object_gate("external", "PROTOCOL-2.1-fresh-exchange", root)
    assert gate["status"] == "PASS", gate["findings"]
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] != rows[0]["selected_package_check"]["replay"]["request"]["nonce"]


LEGAL_STATES = ["CREATED_REQUEST", "LAUNCHED_FIXED_WORKER", "DECODED_BOUND_REPLY"]


def _states(events: list[dict[str, Any]]) -> list[str]:
    return [event["state"] for event in events]


def test_observation_exposes_exact_legal_exchange_transcripts(observations: dict[str, Any]) -> None:
    """PROTOCOL-0.1 transitions must be observed at the parent/worker boundary, not implied by aliases."""
    assert [_states(row["transcript"]) for row in observations["real"]] == [LEGAL_STATES, LEGAL_STATES]
    assert [row["transcript"][1]["participant"] for row in observations["real"]] == ["fixed_worker", "fixed_worker"]
    seqs = [event["seq"] for row in observations["real"] for event in row["transcript"]]
    assert seqs == sorted(set(seqs)) and len(seqs) == 6


def test_observation_records_parent_execution_for_each_exchange(observations: dict[str, Any]) -> None:
    """Each accepted exchange has a parent-side record that verifies against the decoded reply."""
    for row in observations["real"]:
        assert row["parent_record"]["outcome"] == "ACCEPTED"
        assert row["reply"]["request"] == row["request"]


def test_declared_compatibility_and_not_established_fields_are_executable() -> None:
    """PROTOCOL-0.2/0.3 fields: compatibility, message authority and liveness must be declared, not prose-only."""
    from verifier.runtime import local_ledger_execution as peer
    # The accepted peer pair must track the peer's own constants, so drift fails here.
    assert execution.COMPATIBILITY == {
        "protocol_request": execution.REQUEST_SCHEMA, "protocol_observation": execution.OBSERVATION_SCHEMA,
        "peer_request": peer.REQUEST_SCHEMA, "peer_observation": peer.OBSERVATION_SCHEMA,
        "negotiation": "exact-declared-version-or-refusal"}
    for row in execution.catalog():
        assert row["not_established"]["message_authority"].strip() and row["not_established"]["liveness"].strip()


def test_route_prose_names_mechanized_states_and_recovery() -> None:
    claims = {row["coordinate"]: row["exact_claim"] for row in execution.catalog()}
    for term in LEGAL_STATES + ["FAILED_TRANSPORT", "REJECTED_REPLY", "parent_record"]:
        assert term in claims["PROTOCOL-1.1"] or term in claims["PROTOCOL-2.2"] or term in claims["PROTOCOL-1.2"]
    assert "recovery" in claims["PROTOCOL-2.2"].lower()


@pytest.mark.parametrize("coordinate,mutate", [
    # Current checker ignores these added fields, so accepting them is the RED.
    ("PROTOCOL-1.2", lambda obs: obs["faults"].__setitem__("downgrade", {
        "returned": True, "exception": None, "reason": None, "calls": 1, "response_bytes": 10})),
    ("PROTOCOL-1.2", lambda obs: obs["faults"].__setitem__("truncated", {
        "returned": True, "exception": None, "reason": None, "calls": 1, "response_bytes": 10})),
    ("PROTOCOL-2.2", lambda obs: obs["faults"]["timeout"].__setitem__("recovery", "RECOVERED")),
    ("PROTOCOL-2.2", lambda obs: obs["faults"]["exit"].__setitem__("recovery", "RECOVERED")),
    ("PROTOCOL-2.2", lambda obs: obs["faults"]["timeout"].__setitem__("transcript", [
        {"seq": 0, "state": "CREATED_REQUEST", "participant": "parent_dispatcher"},
        {"seq": 1, "state": "LAUNCHED_FIXED_WORKER", "participant": "fixed_worker"},
        {"seq": 2, "state": "DECODED_BOUND_REPLY", "participant": "parent_dispatcher"}])),
])
def test_forged_compatibility_or_recovery_is_refused(observations: dict[str, Any], coordinate: str, mutate: Any) -> None:
    changed = deepcopy(observations)
    mutate(changed)
    assert not execution.check_observations(coordinate, changed)


def _swap_states(events: list[dict[str, Any]], left: int, right: int) -> None:
    for key in ("state", "participant"):
        events[left][key], events[right][key] = events[right][key], events[left][key]


TRANSCRIPT_MUTATIONS = {
    "skipped_launch": lambda real: real[0]["transcript"].pop(1),
    "reordered_states": lambda real: _swap_states(real[0]["transcript"], 0, 1),
    "duplicate_created": lambda real: real[0]["transcript"].insert(1, dict(real[0]["transcript"][0])),
    "unknown_state": lambda real: real[0]["transcript"][2].__setitem__("state", "SENT_REQUEST"),
    "swapped_participant": lambda real: real[0]["transcript"][1].__setitem__("participant", "parent_dispatcher"),
    "interleaved_sequence": lambda real: real[1]["transcript"][0].__setitem__("seq", real[0]["transcript"][0]["seq"]),
    "forged_worker_digest": lambda real: real[0]["transcript"][1].__setitem__("worker_sha256", "sha256:" + "0" * 64),
    "missing_parent_record": lambda real: real[0].__setitem__("parent_record", None),
    "parent_outcome_rewritten": lambda real: real[0]["parent_record"].__setitem__("outcome", "REJECTED"),
    "replayed_reply_for_second_exchange": lambda real: real[1].__setitem__("reply", deepcopy(real[0]["reply"])),
}


@pytest.mark.parametrize("name", sorted(TRANSCRIPT_MUTATIONS))
def test_transcript_and_parent_record_mutations_are_refused(observations: dict[str, Any], name: str) -> None:
    changed = deepcopy(observations)
    TRANSCRIPT_MUTATIONS[name](changed["real"])
    assert not execution.check_observations("PROTOCOL-1.1", changed)


@pytest.mark.parametrize("coordinate,name", [
    ("PROTOCOL-2.2", "timeout"),
    ("PROTOCOL-2.2", "exit"),
    ("PROTOCOL-1.2", "downgrade"),
    ("PROTOCOL-1.2", "truncated"),
    ("PROTOCOL-3.1", "recapture"),
])
def test_fault_rows_reach_exactly_their_terminal_state(observations: dict[str, Any], coordinate: str, name: str) -> None:
    """Each injected failure is one legal attempt ending in its declared terminal state and recovery."""
    row = observations["faults"][name]
    assert row["recovery"] in {"NO_RETRY_UNAVAILABLE", "NO_RETRY_REFUSED"} and row["calls"] == 1
    assert len(row["transcript"]) == 3 and row["transcript"][-1]["participant"] == "parent_dispatcher"
    assert execution.check_observations(coordinate, observations)


@pytest.mark.parametrize("coordinate,name", [("PROTOCOL-2.2", "timeout"), ("PROTOCOL-2.2", "exit")])
def test_forged_retry_after_failure_is_refused(observations: dict[str, Any], coordinate: str, name: str) -> None:
    changed = deepcopy(observations)
    changed["faults"][name]["transcript"] = changed["faults"][name]["transcript"] * 2
    assert not execution.check_observations(coordinate, changed)
