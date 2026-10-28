"""Fresh simulated CONTROLLER and ACTUATOR checks for Verifier Standard (VSTD).

Terminology: hash-based message authentication code (HMAC); JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import base64
from copy import deepcopy
import dataclasses
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.runtime import emulator_control_execution as execution, emulator_control_worker as worker, package_execution
from verifier.runtime import local_ledger_worker as ledger_worker
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.tier_zero_profile import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
OWNED_SOURCES = (
    ROOT / "src" / "verifier" / "runtime" / "emulator_control_execution.py",
    ROOT / "src" / "verifier" / "runtime" / "emulator_control_worker.py",
)


NAMES = {
    "CONTROLLER-1.1-lifecycle-feedback-and-command-authority",
    "CONTROLLER-2.1-capacity-timing-and-stability-boundary",
    "CONTROLLER-3.1-intervention-partial-failure-and-recovery",
    "ACTUATOR-1.1-simulated-command-to-effect",
    "ACTUATOR-2.1-response-capacity-and-saturation",
    "ACTUATOR-3.1-feedback-interlocks-and-failure",
}
COORDINATES = (
    "CONTROLLER-1.1",
    "CONTROLLER-2.1",
    "CONTROLLER-3.1",
    "ACTUATOR-1.1",
    "ACTUATOR-2.1",
    "ACTUATOR-3.1",
)
_MISSING = object()
_REQUEST = {
    "schema_version": execution.REQUEST_SCHEMA,
    "nonce": "emulated-control-regression",
    "object_id": "emulated-control",
    "object_digest": "sha256:" + "1" * 64,
    "collection_digest": "sha256:" + "2" * 64,
}
_OBJECTIVE_FIELDS = ("object_id", "object_digest", "collection_digest", "nonce")
_CHALLENGE_NONCE = base64.b64encode(b"control-nonce-0001").decode("ascii")
_OTHER_NONCE = base64.b64encode(b"control-nonce-9999").decode("ascii")
_ZERO_B64 = base64.b64encode(b"\x00" * 32).decode("ascii")


def _mutated(observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]) -> dict[str, Any]:
    changed = deepcopy(observations)
    for path, replacement in edits:
        row: Any = changed
        for part in path[:-1]:
            row = row[part]
        if replacement is _MISSING:
            del row[path[-1]]
        else:
            row[path[-1]] = replacement
    return changed


def _redigested(observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]) -> dict[str, Any]:
    """Apply edits, then recompute the worker verdict digest: a consistent verdict forgery."""
    from verifier.hardware.canonical import canonical_digest

    changed = _mutated(observations, edits)
    verdict = changed["worker_verdict"]
    body = {key: verdict[key] for key in ("schema_version", "attestation_signature", "continuity")}
    verdict["verdict_digest"] = canonical_digest(body)
    return changed


def test_owned_modules_carry_no_vstd_prefixed_pseudo_identifier() -> None:
    """The objective domain is an internal schema discriminator, not a VSTD obligation."""
    from scripts import check_namespace_closure as gate

    for path in OWNED_SOURCES:
        found = sorted(
            token
            for token in gate._tokens_in_text(path.read_text(encoding="utf-8"))
            if not gate.admissible(token)
        )
        assert not found, f"{path.name} carries non-admissible identifiers: {found}"


def test_objective_domain_is_a_lowercase_internal_schema_identifier() -> None:
    assert execution.OBJECTIVE_DOMAIN == "verifier-emulated-control-objective-1"
    assert worker.OBJECTIVE_DOMAIN == execution.OBJECTIVE_DOMAIN


def test_emulated_control_has_six_reasoned_bounded_routes() -> None:
    routes = execution.catalog()
    assert {row["obligation_id"] for row in routes} == NAMES
    assert [row["object_kind"] for row in routes] == [
        "CONTROLLER",
        "CONTROLLER",
        "CONTROLLER",
        "ACTUATOR",
        "ACTUATOR",
        "ACTUATOR",
    ]
    assert [row["tier"] for row in routes] == [1, 2, 3, 1, 2, 3]
    assert all(row["reason"].strip() and row["exact_claim"].strip() for row in routes)
    boundary = execution.BOUNDARY
    assert "TEST_HMAC_FIXTURE" in boundary
    for excluded in (
        "not physical calibration",
        "physical stability",
        "physical attestation",
        "real-world actuation",
        "safe-state proof",
        "measured latency",
        "command authority",
        "parent does not verify HMAC",
    ):
        assert excluded in boundary


def test_semantic_version_and_observation_schema_are_bumped() -> None:
    routes = execution.catalog()
    assert {row["semantic_version"] for row in routes} == {"verifier-emulated-control-obligations-2"}
    assert execution.OBSERVATION_SCHEMA == "verifier-emulated-control-observations-2"


def _route(coordinate: str) -> dict[str, Any]:
    return next(row for row in execution.catalog() if row["coordinate"] == coordinate)


@pytest.mark.parametrize(
    "coordinate,phrases",
    [
        ("CONTROLLER-1.1", ("objectives", "NOT_ESTABLISHED")),
        ("CONTROLLER-2.1", ("stability", "NOT_ESTABLISHED")),
        ("CONTROLLER-3.1", ("feedback loss", "competing", "NOT_ESTABLISHED")),
        ("ACTUATOR-1.1", ("physical effect", "NOT_ESTABLISHED")),
        ("ACTUATOR-2.1", ("frame", "NOT_ESTABLISHED")),
        ("ACTUATOR-3.1", ("recovery", "NOT_ESTABLISHED")),
    ],
)
def test_route_claims_name_each_unmechanized_field_as_not_established(
    coordinate: str, phrases: tuple[str, ...]
) -> None:
    route = _route(coordinate)
    text = (route["reason"] + " " + route["exact_claim"]).lower()
    for phrase in phrases:
        assert phrase.lower() in text, phrase


_FORBIDDEN_OVERSTATEMENTS = (
    "physical stability is established",
    "safe state is established",
    "safe-state is established",
    "physical attestation is established",
    "real-world actuation is established",
    "measured latency is established",
    "hmac authenticity is established",
    "parent verifies hmac",
    "physically calibrated",
    "proves physical",
)


@pytest.mark.parametrize(
    "coordinate,phrases",
    [
        ("CONTROLLER-1.1", ("worker-side", "command authority", "NOT_ESTABLISHED")),
        ("CONTROLLER-2.1", ("measured latency", "external stability", "NOT_ESTABLISHED")),
        ("CONTROLLER-3.1", ("feedback loss", "competing", "same-partition", "NOT_ESTABLISHED")),
        ("ACTUATOR-1.1", ("real-world actuation", "NOT_ESTABLISHED")),
        ("ACTUATOR-2.1", ("measured response", "NOT_ESTABLISHED")),
        ("ACTUATOR-3.1", ("recovery", "physical recovery", "NOT_ESTABLISHED")),
    ],
)
def test_claims_name_their_boundaries_and_never_overstate(
    coordinate: str, phrases: tuple[str, ...]
) -> None:
    claim = _route(coordinate)["exact_claim"]
    lowered = claim.lower()
    for phrase in phrases:
        assert phrase.lower() in lowered, phrase
    for phrase in _FORBIDDEN_OVERSTATEMENTS:
        assert phrase not in lowered, phrase


def test_controller_failure_claim_mechanizes_feedback_loss_and_competing_commands() -> None:
    claim = _route("CONTROLLER-3.1")["exact_claim"]
    assert "feedback-withdrawal" in claim
    assert "competing" in claim
    assert "distinct partition" in claim
    assert "NOT_ESTABLISHED" in claim


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = dict(_REQUEST)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(execution.__file__).with_name(execution.WORKER)),
        ],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert report["request"] == request
    assert report["source_pins"] == source_pins()
    assert len(result.stdout) < 1024 * 1024
    return report["observations"]


@pytest.mark.parametrize("coordinate", COORDINATES)
def test_actual_emulator_execution_satisfies_finite_claim(
    observations: dict[str, Any], coordinate: str
) -> None:
    assert execution.check_observations(coordinate, observations), observations


@pytest.mark.parametrize(
    "coordinate,path,replacement",
    [
        ("CONTROLLER-1.1", ("normal", "descriptor", "deployment_class"), "physical"),
        ("CONTROLLER-1.1", ("normal", "trust_boundary", "physical_effect_claimed"), True),
        ("CONTROLLER-1.1", ("normal", "topology", "links", 0, "target_node_id"), "missing"),
        ("CONTROLLER-2.1", ("normal", "events", 2, "previous_root"), "0" * 64),
        ("CONTROLLER-2.1", ("normal", "events", 2, "timestamp"), "2026-10-14T23:59:59Z"),
        ("CONTROLLER-2.1", ("capacity", "over_limit", "returned"), True),
        ("CONTROLLER-3.1", ("reset", "anchor_failure", "unchanged"), False),
        ("CONTROLLER-3.1", ("reset", "success", "continuity", "status"), "UNKNOWN"),
        ("CONTROLLER-3.1", ("reset", "success", "reset_epoch", "external_anchor_id"), "different"),
        ("ACTUATOR-1.1", ("normal", "feedback", "feedback_type"), "untyped"),
        ("ACTUATOR-1.1", ("normal", "feedback", "observation", "observation_id"), "different"),
        ("ACTUATOR-1.1", ("normal", "observation", "event_id"), "different"),
        ("ACTUATOR-2.1", ("capacity", "exact_limit_ppm"), [999999]),
        ("ACTUATOR-2.1", ("capacity", "over_limit", "unchanged"), False),
        ("ACTUATOR-3.1", ("controls", "bad_device", "returned"), True),
        ("ACTUATOR-3.1", ("controls", "bad_evidence", "message"), "accepted"),
        ("ACTUATOR-3.1", ("controls", "duplicate_execution", "unchanged"), False),
    ],
)
def test_parent_oracle_refuses_forged_effect_or_control(
    observations: dict[str, Any],
    coordinate: str,
    path: tuple[Any, ...],
    replacement: Any,
) -> None:
    changed = _mutated(observations, ((path, replacement),))
    assert not execution.check_observations(coordinate, changed)


# RED rows for claimed-but-unchecked fields. Every row is accepted by the
# pre-change oracle; the post-change oracle must refuse it.
_UNCHECKED_FIELD_MUTATIONS = [
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "events", 1, "device_identity_id"), "physical:other"),),
        id="commands-one-device-event-identity",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "topology", "nodes", 0, "physical_identity_id"), "physical:other"),),
        id="authority-topology-physical-identity",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "start", "started_at"), "2026-10-15T00:00:09Z"),),
        id="commands-start-row-unbound-to-event-timestamp",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "observation", "extra"), "x"),),
        id="feedback-unknown-row-field",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "events", 0, "sequence"), 0.0),),
        id="timing-type-confused-sequence",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "events", 2, "event_id"), "event:control-0:0:1"),),
        id="commands-duplicate-event-identifier",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        (
            (("normal", "events", 1, "timestamp"), "2026-10-15T00:00:09Z"),
            (("normal", "start", "started_at"), "2026-10-15T00:00:09Z"),
        ),
        id="timing-forged-timestamp-without-root-recomputation",
    ),
    pytest.param(
        "CONTROLLER-2.1",
        ((("normal", "start", "started_at"), "2026-10-15T00:00:09Z"),),
        id="timing-start-row-unbound",
    ),
    pytest.param(
        "CONTROLLER-2.1",
        ((("capacity", "split_ppm"), [400000.0, 600000]),),
        id="operating-envelope-type-confused-split",
    ),
    pytest.param(
        "CONTROLLER-2.1",
        ((("capacity", "extra"), 1),),
        id="operating-envelope-unknown-capacity-field",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "reset_epoch", "device_identity_id"), "physical:control-0"),),
        id="intervention-cross-device-reset-epoch",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "anchor", "rolling_root"), "0" * 64),),
        id="intervention-anchor-not-bound-to-interrupted-end",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "anchor", "sequence"), 3),),
        id="intervention-anchor-sequence-unbound",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "end", "event_id"), "event:reset-0:0:1"),),
        id="intervention-interrupted-end-aliased-to-start",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "reset_epoch", "prior_epoch"), 1),),
        id="intervention-epoch-transition-unbound",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "events", 0, "extra"), "x"),),
        id="intervention-reset-event-unknown-field",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "anchor_failure", "returned"), 0),),
        id="failure-refusal-type-confused-returned",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "events", 1, "partition_id"), "partition:control-0:b"),),
        id="targets-event-partition-unbound-to-exposure",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "topology", "links", 1, "target_node_id"), "node:logical:partition:control-0:b"),),
        id="targets-exposure-link-rebound",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "end", "outcome"), "INTERRUPTED"),),
        id="simulated-effect-end-outcome-unbound",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "feedback", "callback"), "callback-returned"),),
        id="callback-return-cannot-stand-in-for-effect",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "end", "process_id"), 4242),),
        id="process-launch-cannot-stand-in-for-effect",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "feedback"), _MISSING),),
        id="command-without-feedback-is-incomplete",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "feedback", "effect_domains"), ["SIMULATED", "REAL_PHYSICAL"]),),
        id="mixed-simulated-and-physical-label-cannot-lift-emulator-scope",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "start"), _MISSING),),
        id="fail-closed-missing-required-row",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal",), []),),
        id="fail-closed-non-object-normal-trace",
    ),
    pytest.param(
        "ACTUATOR-2.1",
        ((("normal", "feedback", "observation", "quantities", 0, "unit"), "seconds"),),
        id="units-and-frames-unit-unchecked-on-route",
    ),
    pytest.param(
        "ACTUATOR-2.1",
        ((("normal", "feedback", "observation", "quantities", 0, "value"), 42),),
        id="units-and-frames-type-confused-value",
    ),
    pytest.param(
        "ACTUATOR-2.1",
        (
            (("normal", "observation", "observed_at"), "2026-10-15T00:00:00Z"),
            (("normal", "feedback", "observation", "observed_at"), "2026-10-15T00:00:00Z"),
        ),
        id="response-feedback-before-command-start",
    ),
    pytest.param(
        "ACTUATOR-3.1",
        ((("normal", "feedback", "feedback_type"), "untyped"),),
        id="effect-feedback-unchecked-on-interlock-route",
    ),
    pytest.param(
        "ACTUATOR-3.1",
        ((("controls", "duplicate_execution", "returned"), 0),),
        id="interlock-refusal-type-confused-returned",
    ),
    pytest.param(
        "ACTUATOR-3.1",
        ((("controls", "extra"), {}),),
        id="interlock-unknown-control-row",
    ),
    pytest.param(
        "ACTUATOR-3.1",
        ((("controls", "bad_device"), _MISSING),),
        id="removed-interlock-response-is-incomplete",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "verification_failure"), _MISSING),),
        id="missing-failure-response-is-incomplete",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "descriptor", "vendor"), "OTHER"),),
        id="authority-descriptor-identity-unbound",
    ),
    pytest.param(
        "ACTUATOR-2.1",
        ((("normal", "descriptor", "family"), "OtherFamily"),),
        id="units-and-frames-descriptor-family-unbound",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "command_bindings", "start_event_id"), "event:control-0:0:9"),),
        id="commands-binding-start-event-unchecked-on-effect-route",
    ),
    pytest.param(
        "CONTROLLER-1.1",
        ((("normal", "events", 0, "event_id"), "event:forged-boot"),),
        id="authority-device-boot-event-identifier-unbound",
    ),
    pytest.param(
        "CONTROLLER-3.1",
        ((("reset", "success", "events", 3, "event_id"), "event:reset-0:0:3"),),
        id="intervention-reset-event-identifier-unbound",
    ),
    pytest.param(
        "ACTUATOR-1.1",
        ((("normal", "extra"), "x"),),
        id="commands-unknown-normal-trace-field",
    ),
]


def test_reordered_or_duplicated_trace_rows_are_refused(observations: dict[str, Any]) -> None:
    events = observations["normal"]["events"]
    reordered = _mutated(observations, ((("normal", "events"), [events[0], events[2], events[1], events[3]]),))
    duplicated = _mutated(observations, ((("normal", "events"), [events[0], events[1], events[1], events[3]]),))
    for coordinate in ("CONTROLLER-1.1", "ACTUATOR-1.1"):
        assert not execution.check_observations(coordinate, reordered)
        assert not execution.check_observations(coordinate, duplicated)
    assert execution.check_observations("CONTROLLER-1.1", observations)


@pytest.mark.parametrize("coordinate,edits", _UNCHECKED_FIELD_MUTATIONS)
def test_unchecked_field_mutations_are_refused(
    observations: dict[str, Any],
    coordinate: str,
    edits: tuple[tuple[Any, Any], ...],
) -> None:
    assert execution.check_observations(coordinate, observations)
    assert not execution.check_observations(coordinate, _mutated(observations, edits))


def test_worker_rejects_open_or_caller_selected_request() -> None:
    worker = str(Path(execution.__file__).with_name(execution.WORKER))
    request = dict(_REQUEST, command="caller-selected")
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", worker],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert b"closed bounded emulated-control request required" in result.stderr


def test_worker_rejects_request_whose_object_digest_is_not_a_sha256_digest() -> None:
    worker = str(Path(execution.__file__).with_name(execution.WORKER))
    request = dict(_REQUEST, object_digest="not-a-digest")
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", worker],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert b"closed bounded emulated-control request required" in result.stderr


def test_disabled_capacity_interlock_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.hardware.emulator import VirtualVSTDAccelerator
    from verifier.runtime.emulator_control_worker import observe

    original = VirtualVSTDAccelerator.configure_partitions

    def weakened(self, partitions, *, timestamp=None):
        configured = tuple(partitions)
        if sum(row[2] for row in configured) > 1_000_000:
            configured = ((configured[0][0], configured[0][1], 1_000_000),)
        return original(self, configured, timestamp=timestamp)

    monkeypatch.setattr(VirtualVSTDAccelerator, "configure_partitions", weakened)
    altered = observe(_REQUEST)
    assert not execution.check_observations("CONTROLLER-2.1", altered)
    assert not execution.check_observations("ACTUATOR-2.1", altered)


def test_unknown_coordinate_and_open_observation_fail_closed(
    observations: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_COORDINATE_UNREGISTERED"):
        execution.check_observations("CONTROLLER-9.9", observations)
    assert not execution.check_observations("CONTROLLER-1.1", {**observations, "extra": {}})


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("controls", "active_reconfiguration", "returned"), True),
        (("controls", "duplicate_execution", "unchanged"), False),
        (("normal", "feedback", "feedback_type"), "missing"),
    ],
)
def test_controller_intervention_requires_feedback_and_command_arbitration(
    observations: dict[str, Any], path: tuple[str, ...], replacement: Any
) -> None:
    """CONTROLLER-3.1 refuses forged refusal, reset and feedback rows it mechanizes."""
    changed = _mutated(observations, ((path, replacement),))
    assert not execution.check_observations("CONTROLLER-3.1", changed)


# ---------------------------------------------------------------------------
# Objective and workload identity
# ---------------------------------------------------------------------------


def test_objective_and_workload_identity_bind_the_request(observations: dict[str, Any]) -> None:
    objective = observations["objective"]
    assert {field: objective[field] for field in _OBJECTIVE_FIELDS} == {
        field: _REQUEST[field] for field in _OBJECTIVE_FIELDS
    }
    workload = observations["normal"]["execution_identity"]["workload"]
    assert workload["workload_id"] == "workload:emulated-control"
    assert workload["executable_digest"] == "1" * 64
    for coordinate in COORDINATES:
        assert execution.check_observations(coordinate, observations, request=_REQUEST), coordinate


@pytest.mark.parametrize(
    "edits",
    [
        pytest.param((((("objective", "object_digest")), "sha256:" + "9" * 64),), id="objective-digest-echo-changed"),
        pytest.param((((("objective", "objective_digest")), "0" * 64),), id="objective-digest-forged"),
        pytest.param((((("objective", "nonce")), "replayed-nonce"),), id="objective-nonce-not-request"),
        pytest.param(
            ((("normal", "execution_identity", "workload", "workload_id"), "workload:other"),),
            id="workload-id-aliased-to-other-objective",
        ),
        pytest.param(
            ((("normal", "execution_identity", "workload", "executable_digest"), "2" * 64),),
            id="workload-executable-not-objective-digest",
        ),
        pytest.param(
            ((("normal", "execution_identity", "logical_device_ids"), ["logical:partition:control-0:b"]),),
            id="start-payload-logical-device-rebound",
        ),
        pytest.param(
            ((("normal", "execution_identity", "topology_snapshot_id"), "topology:control-0:0:1"),),
            id="start-payload-topology-rebound",
        ),
    ],
)
def test_objective_or_workload_forgery_is_refused(
    observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]
) -> None:
    changed = _mutated(observations, edits)
    assert not execution.check_observations("CONTROLLER-1.1", changed, request=_REQUEST)
    assert not execution.check_observations("ACTUATOR-1.1", changed)


def test_request_objective_mismatch_is_refused_when_request_is_supplied(
    observations: dict[str, Any],
) -> None:
    other_request = dict(_REQUEST, object_id="different-object")
    assert not execution.check_observations("CONTROLLER-1.1", observations, request=other_request)


# ---------------------------------------------------------------------------
# Attestation evidence and worker-side HMAC verification
# ---------------------------------------------------------------------------


def test_attestation_evidence_is_recomputed_against_its_challenge(observations: dict[str, Any]) -> None:
    attestation = observations["normal"]["attestation"]
    assert attestation["challenge"]["nonce_b64"] == _CHALLENGE_NONCE
    assert attestation["evidence"]["challenge_id"] == "challenge-0"
    assert attestation["evidence"]["signature"]["key_id"] == "vstd3-virtual-device-key"
    assert execution.check_observations("CONTROLLER-1.1", observations)


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("normal", "attestation", "challenge", "nonce_b64"), _OTHER_NONCE),
        (("normal", "attestation", "evidence", "nonce_b64"), _OTHER_NONCE),
        (("normal", "attestation", "evidence", "subject_identity_id"), "physical:other"),
        (("normal", "attestation", "evidence", "signature", "signed_digest"), "0" * 64),
        (("normal", "attestation", "evidence", "verification_state"), "FAILED"),
        (("normal", "attestation", "evidence", "signature", "key_id"), "other-key"),
        (("normal", "attestation", "evidence", "signature", "algorithm"), "HMAC-SHA256"),
        (("normal", "attestation", "challenge", "challenge_id"), "challenge-control"),
        (("normal", "attestation", "evidence", "challenge_id"), "challenge-control"),
        (("normal", "attestation", "evidence", "evidence_source_id"), "evidence:other"),
        (("normal", "attestation", "evidence", "extra"), "x"),
        (("normal", "attestation", "evidence", "signature"), _MISSING),
    ],
)
def test_attestation_forgery_or_alias_is_refused(
    observations: dict[str, Any], path: tuple[str, ...], replacement: Any
) -> None:
    changed = _mutated(observations, ((path, replacement),))
    assert not execution.check_observations("CONTROLLER-1.1", changed)


def _honest_device():
    from verifier.hardware.emulator import VirtualVSTDAccelerator
    from verifier.hardware.models import (
        AccountingExactness,
        AccountingMethod,
        AccountingQuantity,
        ExecutionIdentity,
        WorkloadIdentity,
    )

    device = VirtualVSTDAccelerator("hmac-0", "1.0.0", b"vstd-test-hmac-key")
    device.configure_partitions((("partition:hmac-0:a", "virtual-slice", 1_000_000),))
    device.boot(boot_id="hmac-boot", timestamp="2026-10-15T07:00:00Z")
    job = ExecutionIdentity(
        "execution-hmac",
        WorkloadIdentity("workload:hmac", "2" * 64),
        ("logical:partition:hmac-0:a",),
        device.current_topology_snapshot_id,
        "2026-10-15T07:00:01Z",
    )
    device.submit_execution(job, timestamp="2026-10-15T07:00:01Z")
    device.observe_execution(
        job.execution_id,
        (
            AccountingQuantity(
                "issued_operations",
                "42",
                "operations",
                AccountingMethod.FIRMWARE_COUNTER,
                device.evidence_source_id,
                "reference emulator command issue counter",
                AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        timestamp="2026-10-15T07:00:02Z",
    )
    device.complete_execution(job.execution_id, timestamp="2026-10-15T07:00:03Z")
    return device


def test_worker_side_hmac_continuity_refutes_forged_and_aliased_signatures() -> None:
    from verifier.runtime.emulator_control_worker import continuity_verdict

    device = _honest_device()
    keys = {device.key_id: device.signing_key}
    record = device.continuity_record()
    assert continuity_verdict(record, keys) == {
        "status": "PASS",
        "verified_event_count": 4,
        "errors": [],
        "gaps": [],
    }
    forged_event = dataclasses.replace(
        record.events[2],
        signature=dataclasses.replace(record.events[2].signature, signature_b64=_ZERO_B64),
    )
    forged = dataclasses.replace(
        record, events=record.events[:2] + (forged_event,) + record.events[3:]
    )
    verdict = continuity_verdict(forged, keys)
    assert verdict["status"] == "FAIL"
    assert any("signature verification failed" in row for row in verdict["errors"])
    aliased_event = dataclasses.replace(
        record.events[2],
        signature=dataclasses.replace(record.events[2].signature, key_id="unknown-key"),
    )
    aliased = dataclasses.replace(
        record, events=record.events[:2] + (aliased_event,) + record.events[3:]
    )
    assert continuity_verdict(aliased, keys)["status"] == "UNKNOWN"


def test_worker_side_attestation_verdict_refutes_forged_signature() -> None:
    from verifier.runtime.emulator_control_worker import attestation_verdict

    device = _honest_device()
    challenge = device.issue_challenge(
        challenge_id="challenge-hmac",
        nonce=b"hmac-nonce-0001",
        issued_at="2026-10-15T07:00:00Z",
        expires_at="2026-10-15T08:00:00Z",
        verifier_id="emulated-control-worker",
    )
    evidence = device.attest(challenge)
    assert attestation_verdict(evidence, device.signing_key) == "PASS"
    forged = dataclasses.replace(
        evidence, signature=dataclasses.replace(evidence.signature, signature_b64=_ZERO_B64)
    )
    assert attestation_verdict(forged, device.signing_key) == "FAIL"
    rebound = dataclasses.replace(
        evidence, signature=dataclasses.replace(evidence.signature, signed_digest="0" * 64)
    )
    assert attestation_verdict(rebound, device.signing_key) == "FAIL"


def test_parent_does_not_verify_hmac_bytes_by_design(observations: dict[str, Any]) -> None:
    """Documents the trust boundary: HMAC bytes are authenticated worker-side only.

    The parent recomputes rolling roots and digests but holds no fixture key, so
    altered signature bytes are not refuted here; the worker verdict covers them.
    """
    assert observations["normal"]["trust_boundary"]["hmac_verification"] == "WORKER_SIDE_ONLY"
    altered = _mutated(
        observations,
        ((("normal", "events", 2, "signature", "signature_b64"), _ZERO_B64),),
    )
    assert execution.check_observations("CONTROLLER-1.1", altered)


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("normal", "trust_boundary", "hmac_verification"), "PARENT_VERIFIED"),
        (("normal", "trust_boundary", "hmac_key_exposed_to_parent"), True),
        (("normal", "trust_boundary", "hmac_authenticity_beyond_worker"), "ESTABLISHED"),
        (("normal", "trust_boundary", "command_authority"), "ESTABLISHED"),
        (("normal", "trust_boundary", "measured_latency"), "ESTABLISHED"),
        (("normal", "trust_boundary", "real_world_authority"), "ESTABLISHED"),
    ],
)
def test_trust_boundary_cannot_be_overstated(
    observations: dict[str, Any], path: tuple[str, ...], replacement: Any
) -> None:
    assert not execution.check_observations("CONTROLLER-1.1", _mutated(observations, ((path, replacement),)))


def test_worker_verdict_digest_refuses_unrecomputed_edits(observations: dict[str, Any]) -> None:
    assert execution.check_observations("ACTUATOR-1.1", observations)
    plain_edits = [
        (("worker_verdict", "continuity", "normal", "status"), "FAIL"),
        (("worker_verdict", "continuity", "normal", "verified_event_count"), 3),
        (("worker_verdict", "attestation_signature"), "FAIL"),
        (("worker_verdict", "verdict_digest"), "0" * 64),
    ]
    for edit in plain_edits:
        assert not execution.check_observations("ACTUATOR-1.1", _mutated(observations, (edit,))), edit


@pytest.mark.parametrize(
    "edits",
    [
        pytest.param(((("worker_verdict", "continuity", "normal", "verified_event_count"), True),), id="bool-as-int-count"),
        pytest.param(((("worker_verdict", "continuity", "normal", "status"), "FAIL"),), id="normal-continuity-failed"),
        pytest.param(((("worker_verdict", "attestation_signature"), "FAIL"),), id="attestation-signature-failed"),
        pytest.param(((("worker_verdict", "continuity", "feedback_loss", "gaps"), [{}]),), id="gap-injected"),
        pytest.param(((("worker_verdict", "continuity", "extra"), {}),), id="unknown-continuity-check"),
        pytest.param(((("worker_verdict", "extra"), "x"),), id="unknown-verdict-field"),
        pytest.param(((("worker_verdict", "continuity", "reset", "status"), "UNKNOWN"),), id="reset-continuity-unknown-but-redigested"),
    ],
)
def test_consistently_redigested_verdict_forgery_is_refused(
    observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]
) -> None:
    assert not execution.check_observations("ACTUATOR-1.1", _redigested(observations, edits))


# ---------------------------------------------------------------------------
# Feedback loss (CONTROLLER-3.1)
# ---------------------------------------------------------------------------


def test_feedback_loss_ends_interrupted_and_refuses_late_feedback(observations: dict[str, Any]) -> None:
    loss = observations["feedback_loss"]
    assert [row["event_type"] for row in loss["events"]] == ["DEVICE_BOOT", "EXEC_START", "EXEC_END"]
    assert loss["end"]["outcome"] == "INTERRUPTED"
    assert loss["late_feedback"]["returned"] is False
    assert loss["late_feedback"]["unchanged"] is True
    assert execution.check_observations("CONTROLLER-3.1", observations)


_FEEDBACK_LOSS_MUTATIONS = [
    pytest.param(((("feedback_loss", "end", "outcome"), "COMPLETED"),), id="withdrawn-feedback-reported-completed"),
    pytest.param(((("feedback_loss", "late_feedback", "returned"), True),), id="late-feedback-accepted"),
    pytest.param(((("feedback_loss", "late_feedback", "unchanged"), False),), id="late-feedback-changed-state"),
    pytest.param(((("feedback_loss", "late_feedback", "message"), "accepted"),), id="late-feedback-refusal-reworded"),
    pytest.param(((("feedback_loss", "events", 2, "event_type"), "EXEC_OBSERVATION"),), id="end-row-retyped-as-feedback"),
    pytest.param(
        ((("feedback_loss", "events"), None),),
        id="events-replaced-with-null",
    ),
    pytest.param(
        ((("feedback_loss", "end", "event_id"), "event:feedback-0:0:1"),),
        id="end-aliased-to-start-event",
    ),
    pytest.param(
        ((("feedback_loss", "execution", "workload", "workload_id"), "workload:other"),),
        id="workload-aliased",
    ),
    pytest.param(
        ((("feedback_loss", "execution", "topology_snapshot_id"), "topology:control-0:0:0"),),
        id="stale-topology-snapshot",
    ),
    pytest.param(
        ((("feedback_loss", "events", 2, "event_payload_digest"), "0" * 64),),
        id="end-payload-digest-unbound",
    ),
    pytest.param(
        ((("feedback_loss", "extra"), "x"),),
        id="unknown-feedback-loss-field",
    ),
]


@pytest.mark.parametrize("edits", _FEEDBACK_LOSS_MUTATIONS)
def test_feedback_loss_forgery_is_refused(
    observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]
) -> None:
    changed = _mutated(observations, edits)
    assert not execution.check_observations("CONTROLLER-3.1", changed)


def test_reordered_feedback_loss_trace_is_refused(observations: dict[str, Any]) -> None:
    rows = observations["feedback_loss"]["events"]
    swapped = _mutated(observations, ((("feedback_loss", "events"), [rows[0], rows[2], rows[1]]),))
    assert not execution.check_observations("CONTROLLER-3.1", swapped)


# ---------------------------------------------------------------------------
# Competing live command arbitration (CONTROLLER-3.1)
# ---------------------------------------------------------------------------


def test_competing_live_commands_serialize_on_distinct_partitions(observations: dict[str, Any]) -> None:
    arbitration = observations["arbitration"]
    assert [row["event_type"] for row in arbitration["events"]] == [
        "DEVICE_BOOT",
        "EXEC_START",
        "EXEC_START",
        "EXEC_OBSERVATION",
        "EXEC_OBSERVATION",
        "EXEC_END",
        "EXEC_END",
    ]
    assert [row["execution_id"] for row in arbitration["ends"]] == [
        "execution-arb-b",
        "execution-arb-a",
    ]
    assert execution.check_observations("CONTROLLER-3.1", observations)


_ARBITRATION_MUTATIONS = [
    pytest.param(((("arbitration", "accounting", 1, "device_scope_ids"), ["logical:partition:arbitration-0:a"]),), id="feedback-crosses-partitions"),
    pytest.param(((("arbitration", "accounting", 0, "execution_id"), "execution-arb-b"),), id="feedback-attributed-to-other-command"),
    pytest.param(((("arbitration", "ends", 0, "execution_id"), "execution-arb-a"),), id="end-attributed-to-other-command"),
    pytest.param(((("arbitration", "ends", 1, "outcome"), "INTERRUPTED"),), id="end-outcome-rewritten"),
    pytest.param(((("arbitration", "starts", 1, "event_id"), "event:arbitration-0:0:1"),), id="second-start-aliased-to-first"),
    pytest.param(((("arbitration", "observations", 1, "accounting_observation_id"), "accounting:execution-arb-a:0"),), id="observation-id-aliased"),
    pytest.param(((("arbitration", "executions", 1, "topology_snapshot_id"), "topology:arbitration-0:0:1"),), id="competing-command-stale-topology"),
    pytest.param(((("arbitration", "events", 0, "device_identity_id"), "physical:control-0"),), id="cross-device-boot-row"),
    pytest.param(((("arbitration", "events", 4, "partition_id"), "partition:arbitration-0:a"),), id="event-partition-rebound"),
    pytest.param(((("arbitration", "events", 1, "epoch"), 1),), id="epoch-rebound"),
    pytest.param(((("arbitration", "extra"), "x"),), id="unknown-arbitration-field"),
]


@pytest.mark.parametrize("edits", _ARBITRATION_MUTATIONS)
def test_competing_command_forgery_is_refused(
    observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]
) -> None:
    assert not execution.check_observations("CONTROLLER-3.1", _mutated(observations, edits))


def test_reordered_serialized_commands_are_refused(observations: dict[str, Any]) -> None:
    rows = observations["arbitration"]["events"]
    swapped = list(rows)
    swapped[3], swapped[4] = swapped[4], swapped[3]
    assert not execution.check_observations(
        "CONTROLLER-3.1", _mutated(observations, ((("arbitration", "events"), swapped),))
    )


# ---------------------------------------------------------------------------
# Actuator device reset and recovery after an interrupted command (ACTUATOR-3.1)
# ---------------------------------------------------------------------------


def test_actuator_reset_recovers_after_interrupted_command(observations: dict[str, Any]) -> None:
    recovery = observations["recovery"]
    assert [row["event_type"] for row in recovery["events"]] == [
        "DEVICE_BOOT",
        "EXEC_START",
        "EXEC_END",
        "RESET",
        "EXEC_START",
        "EXEC_OBSERVATION",
        "EXEC_END",
    ]
    assert recovery["interrupted_end"]["outcome"] == "INTERRUPTED"
    assert recovery["recovered_end"]["outcome"] == "COMPLETED"
    assert recovery["recovered_execution"]["topology_snapshot_id"] == "topology:recovery-0:1:0"
    assert execution.check_observations("ACTUATOR-3.1", observations)


_RECOVERY_MUTATIONS = [
    pytest.param(((("recovery", "reset_epoch", "prior_rolling_root"), "0" * 64),), id="epoch-not-chained-to-interrupted-end"),
    pytest.param(((("recovery", "anchor", "rolling_root"), "0" * 64),), id="anchor-not-bound-to-interrupted-end"),
    pytest.param(((("recovery", "anchor", "signature", "signed_digest"), "0" * 64),), id="anchor-signature-rebound"),
    pytest.param(((("recovery", "interrupted_end", "outcome"), "COMPLETED"),), id="interrupted-command-reported-completed"),
    pytest.param(((("recovery", "recovered_execution", "topology_snapshot_id"), "topology:recovery-0:0:0"),), id="recovered-command-on-pre-reset-topology"),
    pytest.param(((("recovery", "recovered_accounting", "execution_id"), "execution-interrupted"),), id="recovered-feedback-attributed-to-interrupted"),
    pytest.param(((("recovery", "reset_epoch", "reason"), "unrelated reason"),), id="reset-reason-rewritten"),
    pytest.param(((("recovery", "reset_epoch", "device_identity_id"), "physical:control-0"),), id="reset-cross-device"),
    pytest.param(((("recovery", "events", 3, "event_payload_digest"), "0" * 64),), id="reset-payload-unbound"),
    pytest.param(((("recovery", "events", 4, "epoch"), 0),), id="recovered-start-rebound-to-old-epoch"),
    pytest.param(((("recovery", "extra"), "x"),), id="unknown-recovery-field"),
]


@pytest.mark.parametrize("edits", _RECOVERY_MUTATIONS)
def test_actuator_recovery_forgery_is_refused(
    observations: dict[str, Any], edits: tuple[tuple[Any, Any], ...]
) -> None:
    assert not execution.check_observations("ACTUATOR-3.1", _mutated(observations, edits))


def test_recovery_continuity_claim_cannot_be_downgraded_without_refusal(
    observations: dict[str, Any],
) -> None:
    downgraded = _redigested(
        observations,
        ((("worker_verdict", "continuity", "recovery", "status"), "UNKNOWN"),),
    )
    assert not execution.check_observations("ACTUATOR-3.1", downgraded)


def test_reordered_recovery_trace_is_refused(observations: dict[str, Any]) -> None:
    rows = list(observations["recovery"]["events"])
    rows[3], rows[4] = rows[4], rows[3]
    assert not execution.check_observations(
        "ACTUATOR-3.1", _mutated(observations, ((("recovery", "events"), rows),))
    )


# ---------------------------------------------------------------------------
# Chain-consistent forgeries: only the semantic gates can refuse these.
# ---------------------------------------------------------------------------


def _rechained(observations: dict[str, Any], scenario: str, index: int, payload: Any) -> dict[str, Any]:
    """Replace one event payload and recompute digests and rolling roots forward.

    The result is a consistent forgery: the rolling chain verifies, so only the
    semantic gates can refuse it. HMAC signature bytes stay stale because the
    parent never verifies them.
    """
    from verifier.hardware.canonical import canonical_digest
    from verifier.hardware.continuity import next_rolling_root
    from verifier.hardware.models import EventType

    changed = deepcopy(observations)
    rows = changed[scenario]["events"]
    rows[index]["event_payload_digest"] = canonical_digest(payload)
    for position in range(index, len(rows)):
        row = rows[position]
        if position > index and row["epoch"] == rows[position - 1]["epoch"]:
            row["previous_root"] = rows[position - 1]["rolling_root"]
        row["rolling_root"] = next_rolling_root(
            row["previous_root"],
            event_type=EventType(row["event_type"]),
            device_identity_id=row["device_identity_id"],
            partition_id=row["partition_id"],
            execution_id=row["execution_id"],
            epoch=row["epoch"],
            sequence=row["sequence"],
            timestamp=row["timestamp"],
            event_payload_digest=row["event_payload_digest"],
        )
        row["signature"]["signed_digest"] = row["rolling_root"]
    return changed


def test_rechained_fixture_is_itself_a_valid_chain(observations: dict[str, Any]) -> None:
    """Control: recomputing an unchanged payload reproduces the worker's own chain."""
    same = _rechained(observations, "normal", 1, observations["normal"]["execution_identity"])
    assert same["normal"]["events"] == observations["normal"]["events"]
    assert execution.check_observations("CONTROLLER-1.1", same)


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param(("workload", "workload_id"), "workload:other", id="workload-object-rebound"),
        pytest.param(("workload", "executable_digest"), "2" * 64, id="executable-not-objective"),
        pytest.param(("logical_device_ids",), ["logical:partition:control-0:b"], id="logical-device-rebound"),
    ],
)
def test_chain_consistent_workload_forgery_is_refused_by_objective_binding(
    observations: dict[str, Any], field: tuple[str, ...], value: Any
) -> None:
    identity = deepcopy(observations["normal"]["execution_identity"])
    target = identity
    for part in field[:-1]:
        target = target[part]
    target[field[-1]] = value
    forged = _rechained(observations, "normal", 1, identity)
    forged["normal"]["execution_identity"] = identity
    assert not execution.check_observations("CONTROLLER-1.1", forged)


def test_chain_consistent_feedback_scope_forgery_is_refused_by_scope_gate(
    observations: dict[str, Any],
) -> None:
    accounting = deepcopy(observations["arbitration"]["accounting"][1])
    accounting["device_scope_ids"] = ["logical:partition:arbitration-0:a"]
    forged = _rechained(observations, "arbitration", 4, accounting)
    forged["arbitration"]["accounting"][1] = accounting
    assert not execution.check_observations("CONTROLLER-3.1", forged)


def test_chain_consistent_recovered_feedback_scope_forgery_is_refused(
    observations: dict[str, Any],
) -> None:
    accounting = deepcopy(observations["recovery"]["recovered_accounting"])
    accounting["device_scope_ids"] = ["logical:partition:recovery-0:b"]
    forged = _rechained(observations, "recovery", 5, accounting)
    forged["recovery"]["recovered_accounting"] = accounting
    assert not execution.check_observations("ACTUATOR-3.1", forged)


@pytest.mark.parametrize(
    "coordinate,edits",
    [
        pytest.param(
            "CONTROLLER-3.1",
            ((("arbitration", "accounting", 0, "evidence_source_ids"), ["evidence:other"]),),
            id="arbitration-feedback-source-rebound-payload-only",
        ),
        pytest.param(
            "ACTUATOR-3.1",
            ((("recovery", "recovered_accounting", "evidence_source_ids"), ["evidence:other"]),),
            id="recovered-feedback-source-rebound-payload-only",
        ),
    ],
)
def test_feedback_payload_fields_are_bound_by_their_digest_alone(
    observations: dict[str, Any], coordinate: str, edits: tuple[tuple[Any, Any], ...]
) -> None:
    assert not execution.check_observations(coordinate, _mutated(observations, edits))


# ---------------------------------------------------------------------------
# Live package path: the executed request must bind the observation objective
# ---------------------------------------------------------------------------
#
# Only the subprocess boundary is replaced. ``execute_bound`` builds the real
# request, ``verify_accepted`` rechecks the parent record, and ``evaluate_selected``
# runs the real checker. The fake worker echoes the request the parent submitted
# but serves observations that the real installed worker produced for another
# request. Those observations are self-consistent, so only request binding can
# refuse them.

_REAL_RUN = subprocess.run
_OTHER_REQUEST = dict(_REQUEST, object_id="other-object", nonce="swapped-request-0002")


def _worker_observations(request: dict[str, Any]) -> dict[str, Any]:
    """Run the installed reference worker on an arbitrary request; return only its observations."""
    result = _REAL_RUN(
        [sys.executable, "-I", "-S", "-B", str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout)["observations"]


def _live_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    serve: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    checker: Callable[..., bool] | None = None,
    after: Callable[[int], None] | None = None,
) -> SimpleNamespace:
    """Build one live-path snapshot whose worker launch is a recording substitute.

    ``serve`` maps the submitted request to the observations the fake worker
    reports. ``launches`` counts subprocess launches; ``submitted`` and ``served``
    retain the exchanged request and observations so a test can compare the
    accepted record with what the worker actually produced. ``after`` runs once
    the fake child has reported, with the launch count, so source can move mid-launch.
    """
    root = Path(__file__).resolve().parents[1]
    item = NamespaceObject.create("emulated-control", "OBJECT", {}, {})
    digest = "sha256:" + hashlib.sha256((root / execution.IMPLEMENTATION).read_bytes()).hexdigest()
    selection = {
        "object_id": item.object_id,
        "mechanism": execution.ADAPTER,
        "reason": "Live request-binding control for the emulator package path.",
        "evidence": [{"path": execution.IMPLEMENTATION, "sha256": digest}],
    }

    def read(ref: dict[str, str]) -> bytes:
        data = (root / ref["path"]).read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != ref["sha256"]:
            raise OSError("PACKAGE_EXECUTION_SOURCE_CHANGED")
        return data

    snapshot = SimpleNamespace(
        root=root,
        rows={item.object_id: {"surfaces": ["file:" + execution.IMPLEMENTATION]}},
        collection_digest="sha256:" + "b" * 64,
        read=read,
        execution_transports={},
        executions={},
        execution_failures={},
        execution_checks={(item.object_id, execution.ADAPTER): selection},
    )

    launches: list[dict[str, Any]] = []
    submitted: list[dict[str, Any]] = []
    served: list[dict[str, Any]] = []

    def run(_command: list[str], **kwargs: Any) -> SimpleNamespace:
        launches.append(kwargs)
        request = json.loads(kwargs["input"].decode())
        submitted.append(request)
        observations = serve(request)
        served.append(observations)
        report = {
            "schema_version": execution.OBSERVATION_SCHEMA,
            "request": request,
            "source_pins": ledger_worker.source_pins(),
            "observations": observations,
        }
        if after is not None:
            after(len(launches))
        return SimpleNamespace(returncode=0, stdout=canonical_bytes(report), stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    if checker is not None:
        monkeypatch.setattr(execution, "check_observations", checker)
    return SimpleNamespace(snapshot=snapshot, item=item, launches=launches,
                           submitted=submitted, served=served)


def _live_package_check(
    monkeypatch: pytest.MonkeyPatch,
    coordinate: str,
    serve: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    checker: Callable[..., bool] | None = None,
) -> dict[str, Any]:
    """Evaluate one emulator route through the live package path with a substituted worker.

    ``serve`` maps the request the parent submitted to the observations the
    fake worker reports. ``checker`` optionally replaces the real checker; it
    must keep the request-bound signature to reach the verdict.
    """
    live = _live_snapshot(monkeypatch, serve, checker=checker)
    result = package_execution.evaluate_selected(live.snapshot, live.item, _route(coordinate))
    assert result is not None
    return result


@pytest.mark.parametrize("coordinate", COORDINATES)
def test_live_package_path_refuses_self_consistent_observations_for_another_request(
    monkeypatch: pytest.MonkeyPatch, coordinate: str
) -> None:
    """RED before the call-site change: the live path accepts another request's valid observations."""
    result = _live_package_check(monkeypatch, coordinate, lambda _submitted: _worker_observations(_OTHER_REQUEST))
    assert result["status"] == "FAIL", result
    assert result["reason"] == "PACKAGE_EXECUTION_OBSERVATION_REFUTED"


@pytest.mark.parametrize(
    "name,serve",
    [
        pytest.param(
            "object-digest",
            lambda submitted: _worker_observations(dict(submitted, object_digest="sha256:" + "9" * 64)),
            id="object-digest-recomputed",
        ),
        pytest.param(
            "nonce",
            lambda submitted: _worker_observations(dict(submitted, nonce="replayed-nonce-0001")),
            id="nonce-recomputed",
        ),
        pytest.param(
            "objective-digest",
            lambda submitted: _forged_objective_digest(submitted),
            id="objective-digest-forged-over-submitted-fields",
        ),
        pytest.param(
            "absent",
            lambda submitted: {key: value for key, value in _worker_observations(submitted).items() if key != "objective"},
            id="objective-echo-absent",
        ),
    ],
)
def test_live_package_path_refuses_request_mutations(
    monkeypatch: pytest.MonkeyPatch, name: str, serve: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    """The mutation rows name the forged field; each must refuse on the live path.

    ``object-digest-recomputed`` and ``nonce-recomputed`` are RED before the change: the
    checker accepts self-consistent observations for another request. The objective
    digest and absent-echo rows are controls that the pre-change checker already refused.
    """
    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", serve)
    assert result["status"] == "FAIL", (name, result)


def _forged_objective_digest(submitted: dict[str, Any]) -> dict[str, Any]:
    """Submitted objective fields paired with the digest of a different objective."""
    observed = _worker_observations(submitted)
    observed["objective"]["objective_digest"] = _worker_observations(_OTHER_REQUEST)["objective"]["objective_digest"]
    return observed


def test_parent_checker_wrapper_cannot_observe_or_replace_the_executed_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An in-process wrapper is integrity uncertainty, never the executed checker."""
    calls: list[dict[str, Any]] = []
    original = execution.check_observations

    # The contract is an exact signature: a ``**kwargs`` wrapper is drift, so the
    # wrapper names ``request`` explicitly.
    def observed_call(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        calls.append({"request": request})
        return original(coordinate, observed, request=request)

    submitted: list[dict[str, Any]] = []
    result = _live_package_check(
        monkeypatch,
        "CONTROLLER-1.1",
        lambda request: submitted.append(request) or _worker_observations(request),
        checker=observed_call,
    )
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result
    assert calls == []


@pytest.mark.parametrize("coordinate", COORDINATES)
def test_live_package_path_accepts_the_genuinely_executed_request(
    monkeypatch: pytest.MonkeyPatch, coordinate: str
) -> None:
    """Positive control: the real worker's own request and observations pass the live path."""
    result = _live_package_check(monkeypatch, coordinate, _worker_observations)
    assert result["status"] == "PASS", result


_DRIFTED_DIGEST = "sha256:" + "0" * 64


def _pin_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """One stable ``source_pins`` binding whose pins the test moves between and during launches.

    Production binds ``source_pins`` once at call entry, so swapping the module attribute
    while a launch is running is invisible to it. Moving the state behind one callable is
    what a changing source tree does, and it also keeps these tests off the live tree.
    """
    state: dict[str, Any] = {"pins": dict(source_pins())}
    monkeypatch.setattr(ledger_worker, "source_pins", lambda: dict(state["pins"]))
    return state


def _drift_emulator_pin(state: dict[str, Any]) -> None:
    """Report pins whose emulator digest no longer matches the installed file."""
    state["pins"]["hardware/emulator.py"] = _DRIFTED_DIGEST


def _unverified_read(ref: dict[str, str]) -> bytes:
    """Byte verification is covered elsewhere; these tests isolate the pin comparison."""
    return b""


def _move_pins_at_launch(state: dict[str, Any], launch: int) -> Callable[[int], None]:
    """Move one emulator pin after the child reports, on the given launch only."""
    def after(count: int) -> None:
        if count == launch:
            state["pins"]["hardware/emulator.py"] = "sha256:" + "7" * 64
    return after


def test_stale_cached_receipt_relaunches_exactly_once_and_binds_current_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED before the change: a receipt bound to earlier source bytes was never relaunched.

    The exact ValueError path is production's post-launch pin comparison; this stale
    cache case must end in one relaunch whose pins are the current pins, and PASS.
    """
    state = _pin_state(monkeypatch)
    live = _live_snapshot(monkeypatch, _worker_observations)
    live.snapshot.read = _unverified_read
    first = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert (first["status"], first["reason"]) == ("PASS", execution.BOUNDARY), first
    _drift_emulator_pin(state)
    second = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-2.1"))
    assert (second["status"], second["reason"]) == ("PASS", execution.BOUNDARY), second
    assert len(live.launches) == 2, "Exactly one relaunch for one stale cached receipt."
    key = (live.item.object_id, execution.ADAPTER)
    assert live.snapshot.executions[key]["source_pins"] == state["pins"]


def test_stale_cached_receipt_moved_during_relaunch_is_unknown_and_not_relaunched_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production ValueError path: the coordinate moves during the one relaunch, so the obligation is UNKNOWN."""
    state = _pin_state(monkeypatch)
    live = _live_snapshot(monkeypatch, _worker_observations, after=_move_pins_at_launch(state, 2))
    live.snapshot.read = _unverified_read
    first = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert first["status"] == "PASS", first
    _drift_emulator_pin(state)
    second = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-2.1"))
    assert (second["status"], second["reason"]) == ("UNKNOWN", "PACKAGE_EXECUTION_SOURCE_CHANGED"), second
    third = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert (third["status"], third["reason"]) == ("UNKNOWN", "PACKAGE_EXECUTION_SOURCE_CHANGED"), third
    assert len(live.launches) == 2, "No retry loop: one relaunch, then no further launch."


def test_unchanged_source_reuses_one_launch_across_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: unchanged pins keep the snapshot cache, so routes share one launch."""
    live = _live_snapshot(monkeypatch, _worker_observations)
    results = [package_execution.evaluate_selected(live.snapshot, live.item, _route(name))
               for name in ("CONTROLLER-1.1", "CONTROLLER-2.1")]
    assert [result["status"] for result in results] == ["PASS", "PASS"], results
    assert len(live.launches) == 1


@pytest.mark.parametrize(
    "verdict",
    [
        pytest.param("yes", id="non-empty-string"),
        pytest.param(1, id="integer-one"),
        pytest.param([True], id="non-empty-list"),
        pytest.param({"ok": True}, id="non-empty-dict"),
        pytest.param(object(), id="object-default-truthy"),
    ],
)
def test_truthy_non_boolean_checker_verdict_is_refused(monkeypatch: pytest.MonkeyPatch, verdict: Any) -> None:
    """A parent-process checker replacement cannot turn any truthy value into PASS."""
    result = _live_package_check(
        monkeypatch, "CONTROLLER-1.1", _worker_observations,
        checker=lambda coordinate, observed, request=None: verdict,
    )
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


@pytest.mark.parametrize("verdict", [None, 0, ""], ids=["none", "integer-zero", "empty-string"])
def test_falsy_non_boolean_checker_verdict_is_not_reported_as_refutation(
    monkeypatch: pytest.MonkeyPatch, verdict: Any
) -> None:
    """A parent-process checker replacement cannot turn a falsy value into FAIL."""
    result = _live_package_check(
        monkeypatch, "CONTROLLER-1.1", _worker_observations,
        checker=lambda coordinate, observed, request=None: verdict,
    )
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


def test_parent_process_boolean_replacements_do_not_supply_verdicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even exact Booleans matter only when emitted by the source-bound child."""
    passed = _live_package_check(
        monkeypatch, "CONTROLLER-1.1", _worker_observations,
        checker=lambda coordinate, observed, request=None: True,
    )
    refuted = _live_package_check(
        monkeypatch, "CONTROLLER-1.1", _worker_observations,
        checker=lambda coordinate, observed, request=None: False,
    )
    assert passed["status"] == "UNKNOWN", passed
    assert refuted["status"] == "UNKNOWN", refuted


@pytest.mark.parametrize("error", [ValueError("checker-boom"), RuntimeError("checker-boom"), KeyError("checker-boom")],
                         ids=["value", "runtime", "key"])
def test_parent_checker_exception_is_never_executed(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """A replaced parent callable is integrity uncertainty and cannot leak its error."""
    def raising(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        raise error

    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", _worker_observations, checker=raising)
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result
    assert "checker-boom" not in result["reason"]


def test_parent_checker_error_replacements_are_both_integrity_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither a semantic-looking code nor a resource error runs in the parent."""
    def unregistered(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")

    def unavailable(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        raise OSError("checker-unavailable")

    coded = _live_package_check(monkeypatch, "CONTROLLER-1.1", _worker_observations, checker=unregistered)
    assert coded["status"] == "UNKNOWN" and coded["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), coded
    resource = _live_package_check(monkeypatch, "CONTROLLER-1.1", _worker_observations, checker=unavailable)
    assert resource["status"] == "UNKNOWN" and resource["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), resource


def _mutate_request_digest(observed: dict[str, Any], request: dict[str, Any]) -> None:
    request["object_digest"] = _DRIFTED_DIGEST


def _mutate_request_nonce(observed: dict[str, Any], request: dict[str, Any]) -> None:
    request["nonce"] = "tampered-nonce-0001"


def _mutate_objective_echo(observed: dict[str, Any], request: dict[str, Any]) -> None:
    observed["objective"]["object_digest"] = _DRIFTED_DIGEST


def _mutate_observation_envelope(observed: dict[str, Any], request: dict[str, Any]) -> None:
    observed.clear()


@pytest.mark.parametrize(
    "mutate",
    [_mutate_request_digest, _mutate_request_nonce, _mutate_objective_echo, _mutate_observation_envelope],
    ids=["request-object-digest", "request-nonce", "observation-objective-echo", "observation-cleared"],
)
def test_checker_mutation_of_executed_views_never_passes(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[dict[str, Any], dict[str, Any]], None]
) -> None:
    """A parent-process mutator never receives the accepted record."""
    def mutating(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        assert request is not None
        mutate(observed, request)
        return True

    live = _live_snapshot(monkeypatch, _worker_observations, checker=mutating)
    result = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result
    accepted = live.snapshot.executions[(live.item.object_id, execution.ADAPTER)]
    assert accepted["request"] == live.submitted[0], "The accepted parent record must be unaltered."
    assert accepted["observations"] == live.served[0], "The accepted parent record must be unaltered."


def test_parent_checker_receives_no_copy_of_the_accepted_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """The source-bound child, not an imported parent callable, receives detached JSON."""
    received: list[tuple[Any, Any]] = []

    def observing(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        received.append((observed, request))
        return True

    live = _live_snapshot(monkeypatch, _worker_observations, checker=observing)
    result = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert result["status"] == "UNKNOWN", result
    assert received == []


def test_parent_checker_cannot_replace_the_retained_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parent callable is refused before it can reach snapshot state."""
    holder: dict[str, SimpleNamespace] = {}

    def tampering(coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        live = holder["live"]
        key = (live.item.object_id, execution.ADAPTER)
        live.snapshot.execution_transports[key] = {**live.snapshot.execution_transports[key], "outcome": "REJECTED"}
        return True

    live = holder["live"] = _live_snapshot(monkeypatch, _worker_observations, checker=tampering)
    result = package_execution.evaluate_selected(live.snapshot, live.item, _route("CONTROLLER-1.1"))
    assert result["status"] == "UNKNOWN", result
    key = (live.item.object_id, execution.ADAPTER)
    assert live.snapshot.execution_transports[key]["outcome"] == "ACCEPTED"


def test_request_binding_declaration_cannot_be_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED before the change: deleting the declaration silently restored the two-argument check."""
    monkeypatch.delattr(execution, "CHECKER_CONTRACT", raising=False)
    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", lambda _submitted: _worker_observations(_OTHER_REQUEST))
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


def test_request_binding_declaration_drift_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED before the change: a contrary declaration was ignored."""
    monkeypatch.setattr(execution, "CHECKER_CONTRACT", "observations-only", raising=False)
    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", lambda _submitted: _worker_observations(_OTHER_REQUEST))
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


def test_emptied_closed_request_bound_set_cannot_downgrade_the_emulator(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED before the change: emptying the set let another request's evidence pass the two-argument check."""
    monkeypatch.setattr(package_execution, "REQUEST_BOUND_ADAPTERS", frozenset())
    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", lambda _submitted: _worker_observations(_OTHER_REQUEST))
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


def test_two_argument_checker_for_a_request_bound_adapter_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED before the change: the dispatcher reached the checker with ``request=`` and surfaced a raw TypeError text."""
    def legacy(coordinate: str, observed: dict[str, Any]) -> bool:
        return True

    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", _worker_observations, checker=legacy)
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


@pytest.mark.parametrize(
    "checker",
    [
        pytest.param(lambda coordinate, observed, **kwargs: True, id="var-keyword-wrapper"),
        pytest.param(lambda coordinate, observed, request=None, extra=None: True, id="extra-parameter"),
        pytest.param(lambda coordinate, observed, *args, request=None: True, id="var-positional"),
    ],
)
def test_checker_signature_drift_is_refused(monkeypatch: pytest.MonkeyPatch, checker: Callable[..., bool]) -> None:
    """RED before the change: any checker shape accepting ``request`` was used as request-bound."""
    result = _live_package_check(monkeypatch, "CONTROLLER-1.1", _worker_observations, checker=checker)
    assert result["status"] == "UNKNOWN", result
    assert result["reason"].startswith("PACKAGE_EXECUTION_CHECKER_"), result


def test_ordinary_parent_checker_replacements_are_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    """Observations-only adapters use fresh source too; parent replacements are UNKNOWN."""
    others = [module for module in package_execution.mechanisms().values() if module is not execution]
    assert len(others) == 6
    for module in others:
        calls: list[tuple[Any, ...]] = []

        def legacy(coordinate: str, observed: dict[str, Any]) -> bool:
            calls.append((coordinate, observed))
            return True

        monkeypatch.setattr(module, "check_observations", legacy)
        executed = {"observations": {"value": 1}, "request": {"nonce": "unused"}}
        with pytest.raises(OSError, match="PACKAGE_EXECUTION_CHECKER_"):
            package_execution.check_executed(module, "ORDINARY-1.1", executed)
        assert calls == [], module.ADAPTER
