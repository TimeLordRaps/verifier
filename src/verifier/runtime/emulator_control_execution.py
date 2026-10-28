"""Finite simulated CONTROLLER and ACTUATOR checks for Verifier Standard (VSTD).

Terminology: hash-based message authentication code (HMAC).

The selected implementation is the reference firmware emulator. Its commands,
feedback, capacity, reset, feedback-withdrawal, competing-command and recovery
transitions are executable software observations; they do not establish
physical calibration, physical stability, physical attestation, real-world
actuation or a physical safe state. Hash-based message authentication code
(HMAC) signatures in this path use test fixture keys only, and the fixture keys
are held by the worker: this parent recomputes digests and rolling roots but
does not verify HMAC bytes.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import value_digest


ADAPTER = "verifier-emulated-control-1"
SEMANTIC_VERSION = "verifier-emulated-control-obligations-2"
IMPLEMENTATION = "src/verifier/hardware/emulator.py"
WORKER = "emulator_control_worker.py"
REQUEST_SCHEMA = "verifier-emulated-control-request-1"
OBSERVATION_SCHEMA = "verifier-emulated-control-observations-2"
# ``check_observations`` also receives the executed request, binding the objective echo
# to what the parent sent. The package dispatcher validates this declaration against
# its closed expected set and against the checker signature, and never falls back.
CHECKER_CONTRACT = "request-bound"
VERDICT_SCHEMA = "verifier-emulated-control-worker-verdict-1"
OBJECTIVE_DOMAIN = "verifier-emulated-control-objective-1"
BOUNDARY = (
    "Fresh bounded executions of the exact owned reference emulator, including "
    "typed software feedback, finite partition capacity, local reset rollback, "
    "feedback withdrawal, serialized competing commands on distinct partitions and "
    "actuator-device recovery. TEST_HMAC_FIXTURE is test authentication only and is "
    "verified worker-side; the parent does not verify HMAC bytes; not physical "
    "calibration, physical stability, physical attestation, real-world actuation, "
    "real-world authority, command authority, measured latency, safe-state proof, "
    "complete kind conformance or package polish."
)
_CONTRACTS = (
    ("CONTROLLER-1.1", "lifecycle-feedback-and-command-authority", "CONTROLLER", 1,
     "A controller claim needs an identified command boundary and typed feedback; naming a controller does not establish which implementation accepted a command.",
     "A fresh reference-emulator lifecycle binds one physical emulator identity, its fixed topology, boot, execution start, typed simulated accounting feedback and completion. Event rolling roots and the start, feedback and completion payload digests are recomputed from observed rows; the execution workload is bound to the request objective digest; and the attestation evidence is recomputed against its challenge nonce and signed digest. HMAC continuity and signature checks run worker-side only; the parent verifies a digest over that worker verdict, not the HMAC bytes. Objectives beyond the request digest, command authority, issuer authority and HMAC authenticity beyond the worker boundary are NOT_ESTABLISHED."),
    ("CONTROLLER-2.1", "capacity-timing-and-stability-boundary", "CONTROLLER", 2,
     "Capacity, event order and operating envelope bound the observed controller response; finite emulator traces cannot establish continuous or physical stability.",
     "The finite trace has exact scripted timestamps bound to its start, feedback and completion rows, ordered timestamps, and configured simulated partitions that exactly fill 1000000 ppm without exceeding it. Measured latency, external stability and physical stability are NOT_ESTABLISHED; this route checks finite emulator timing only."),
    ("CONTROLLER-3.1", "intervention-partial-failure-and-recovery", "CONTROLLER", 3,
     "Feedback loss and command arbitration must have executable failure behavior: a failed reset, a withdrawn feedback path or a competing live command must not partially end work or advance local state, and a completed reset must retain its interruption and anchor boundary.",
     "Refused failed anchor, failed anchor verification, active reconfiguration, replayed execution identity and replayed attestation challenge leave simulated state unchanged; a successful reset records an interrupted execution end, an external test anchor bound to that end by rolling root and sequence, an epoch transition bound to that end's rolling root, and a worker-side continuity verification reporting PASS. A feedback-withdrawal scenario ends its execution INTERRUPTED with no accounting event, and late feedback for it is refused with unchanged state. A valid competing command on a distinct partition is accepted, each command keeps its own feedback scope, and the device serializes both into one epoch-local rolling chain. Feedback loss on a physical link, same-partition concurrent arbitration and priority policy are NOT_ESTABLISHED."),
    ("ACTUATOR-1.1", "simulated-command-to-effect", "ACTUATOR", 1,
     "An actuator command requires an observed effect at its declared boundary; method return alone does not establish either a simulated or physical effect.",
     "Submit, observe and complete commands on one logical partition create the corresponding typed reference-emulator events, a COMPLETED end, and simulated accounting feedback whose device scope, partition and quantity are exact. Physical effect, real-world actuation and command authority beyond the fixture key identifier are NOT_ESTABLISHED."),
    ("ACTUATOR-2.1", "response-capacity-and-saturation", "ACTUATOR", 2,
     "Actuation capacity must have an enforced saturation boundary rather than an unbounded declared quantity.",
     "A 1000000 ppm simulated partition is accepted and represented exactly, while 1000001 ppm is refused without configuring a partial device; the normal feedback declares the exact unit operations and the exact string value 42, and feedback arrives strictly between submission and completion. Physical units, measured response time and coordinate frames are NOT_ESTABLISHED: the accounting quantity declares no coordinate frame and this route orders scripted events only."),
    ("ACTUATOR-3.1", "feedback-interlocks-and-failure", "ACTUATOR", 3,
     "Invalid target, topology, evidence, quantity, replay and live reconfiguration inputs must be interlocked before they alter the simulated effect history, and an interrupted command must leave the actuator device recoverable.",
     "Normal typed simulated feedback is bound to the executed command, and active reconfiguration, unknown device, stale topology, wrong evidence source, empty quantity, duplicate execution and duplicate challenge controls are refused with exact messages and unchanged simulated state. On a separate actuator device, an interrupted command is ended INTERRUPTED, a reset epoch is anchored to that end's rolling root, and a later command completes on the post-reset topology with worker-side continuity reporting PASS: recovery of the simulated device only. Physical recovery, hardware fault recovery and recovery after real power loss or tampering are NOT_ESTABLISHED."),
)
_DEVICE = "physical:control-0"
_RESET_DEVICE = "physical:reset-0"
_FEEDBACK_DEVICE = "physical:feedback-0"
_ARBITRATION_DEVICE = "physical:arbitration-0"
_RECOVERY_DEVICE = "physical:recovery-0"
_RECOVERY_BOOT = "recovery-1"
_RECOVERY_REASON = "controlled actuator recovery after interrupted command"
_OBJECTIVE_FIELDS = ("object_id", "object_digest", "collection_digest", "nonce")
_CHALLENGE_NONCE = base64.b64encode(b"control-nonce-0001").decode("ascii")
_KEY_ID = "vstd3-virtual-device-key"
_ANCHOR_KEY_ID = "control-anchor-key"
_HMAC = "HMAC-SHA256-TEST-ONLY"
_EVENT_KEYS = frozenset({
    "device_identity_id", "epoch", "event_id", "event_payload_digest", "event_type",
    "execution_id", "partition_id", "previous_root", "rolling_root", "sequence",
    "signature", "timestamp",
})
_SIGNATURE_KEYS = frozenset({"algorithm", "key_id", "signature_b64", "signed_digest"})
_CONTROL_NAMES = frozenset({
    "active_reconfiguration", "bad_device", "bad_topology", "bad_evidence",
    "bad_quantity", "duplicate_execution", "duplicate_challenge",
})
_NORMAL_KEYS = frozenset({
    "attestation", "command_bindings", "descriptor", "end", "events", "execution_identity",
    "feedback", "observation", "start", "topology", "trust_boundary",
})
_OBSERVED_KEYS = frozenset({
    "objective", "normal", "capacity", "controls", "reset", "feedback_loss",
    "arbitration", "recovery", "worker_verdict",
})
_CONTINUITY_KEYS = frozenset({"normal", "feedback_loss", "arbitration", "recovery", "reset"})
def _quantities(evidence_source: str) -> list[dict[str, Any]]:
    """The one exact issue counter, bound to the evidence source of the device that emitted it."""
    return [{
        "name": "issued_operations",
        "value": "42",
        "unit": "operations",
        "method": "FIRMWARE_COUNTER",
        "evidence_source_id": evidence_source,
        "scope": "reference emulator command issue counter",
        "exactness": "EXACT_FOR_DECLARED_SCOPE",
        "uncertainty": "",
        "vendor_extension": "",
    }]
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def catalog() -> list[dict[str, Any]]:
    """Return finite routes; none is a blanket CONTROLLER or ACTUATOR proof."""
    return [
        {
            "coordinate": coordinate,
            "obligation_id": coordinate + "-" + slug,
            "obligation_name": slug.replace("-", " ").capitalize(),
            "object_kind": kind,
            "tier": tier,
            "reason": reason,
            "exact_claim": claim,
            "semantic_version": SEMANTIC_VERSION,
            "proposition_digest": value_digest(
                {"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}
            ),
            "checking_mechanism": "verifier.runtime.emulator_control_execution.evaluate",
            "scope": "fresh_emulated_control_" + slug.replace("-", "_"),
            "adapter": ADAPTER,
        }
        for coordinate, slug, kind, tier, reason, claim in _CONTRACTS
    ]


def _exact(value: Any, expected: Any) -> bool:
    """Compare JSON-shaped evidence without Python bool, int or float coercion."""
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(
            _exact(value[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _exact(left, right) for left, right in zip(value, expected)
        )
    return value == expected


def _refusal(exception: str, message: str, *, unchanged: bool = True) -> dict[str, Any]:
    return {
        "returned": False,
        "exception": exception,
        "message": message,
        "unchanged": unchanged,
    }


def _refused(
    row: dict[str, Any], exception: str, message: str, *, unchanged: bool = True
) -> bool:
    return _exact(row, _refusal(exception, message, unchanged=unchanged))


def _digest(value: Any) -> str:
    from verifier.hardware.canonical import canonical_digest

    return canonical_digest(value)


def _payload(row: Any, payload: Any) -> bool:
    """Recompute an event payload digest; the rolling root then binds the payload."""
    return type(row) is dict and _digest(payload) == row["event_payload_digest"]


def _chain(events: Any, device: str) -> bool:
    """Recompute each epoch-local rolling root from observed row fields.

    The rolling root is a canonical digest of these fields and needs no HMAC
    key, so the parent detects forged timing, identity or partition rows even
    though it cannot verify the fixture signatures.
    """
    from verifier.hardware.continuity import next_rolling_root
    from verifier.hardware.models import EventType

    if type(events) is not list or not events:
        return False
    last: dict[int, dict[str, Any]] = {}
    previous_stamp = ""
    for event in events:
        if (
            type(event) is not dict
            or set(event) != _EVENT_KEYS
            or type(event["signature"]) is not dict
            or set(event["signature"]) != _SIGNATURE_KEYS
        ):
            return False
        epoch, sequence = event["epoch"], event["sequence"]
        if type(epoch) is not int or type(sequence) is not int:
            return False
        if event["device_identity_id"] != device:
            return False
        if event["event_id"] != f"event:{device.split(':', 1)[1]}:{epoch}:{sequence}":
            return False
        prior = last.get(epoch)
        if sequence != (0 if prior is None else prior["sequence"] + 1):
            return False
        # An epoch's first row links to a genesis root that is not recomputed here;
        # the reset record binds the prior epoch's rolling root instead.
        if prior is not None and event["previous_root"] != prior["rolling_root"]:
            return False
        stamp = event["timestamp"]
        if type(stamp) is not str or not _STAMP.fullmatch(stamp) or stamp < previous_stamp:
            return False
        previous_stamp = stamp
        if not all(
            type(event[name]) is str and _HEX64.fullmatch(event[name])
            for name in ("previous_root", "rolling_root", "event_payload_digest")
        ):
            return False
        try:
            kind = EventType(event["event_type"])
        except ValueError:
            return False
        root = next_rolling_root(
            event["previous_root"],
            event_type=kind,
            device_identity_id=device,
            partition_id=event["partition_id"],
            execution_id=event["execution_id"],
            epoch=epoch,
            sequence=sequence,
            timestamp=stamp,
            event_payload_digest=event["event_payload_digest"],
        )
        signature = event["signature"]
        if (
            root != event["rolling_root"]
            or signature["signed_digest"] != root
            or signature["algorithm"] != _HMAC
            or signature["key_id"] != _KEY_ID
            or type(signature["signature_b64"]) is not str
            or not signature["signature_b64"]
        ):
            return False
        last[epoch] = event
    return True


def _topology(topology: Any) -> bool:
    """Exact fixed topology: physical device, two partitions and their exposed logical devices."""
    nodes: list[dict[str, Any]] = [
        {
            "attributes": {},
            "component_kind": "PHYSICAL_DEVICE",
            "logical_identity_id": "",
            "node_id": "node:physical:control-0",
            "parent_node_ids": [],
            "physical_identity_id": _DEVICE,
            "profile_id": "vstd.virtual-firmware-1",
        }
    ]
    links: list[dict[str, Any]] = []
    for name in ("a", "b"):
        partition = "node:partition:control-0:" + name
        logical = "node:logical:partition:control-0:" + name
        nodes.append({
            "attributes": {},
            "component_kind": "PARTITION",
            "logical_identity_id": "",
            "node_id": partition,
            "parent_node_ids": ["node:physical:control-0"],
            "physical_identity_id": "",
            "profile_id": "",
        })
        nodes.append({
            "attributes": {},
            "component_kind": "LOGICAL_DEVICE",
            "logical_identity_id": "logical:partition:control-0:" + name,
            "node_id": logical,
            "parent_node_ids": [partition],
            "physical_identity_id": "",
            "profile_id": "",
        })
        links.append({
            "attributes": {},
            "link_type": "CONTAINS",
            "source_node_id": "node:physical:control-0",
            "target_node_id": partition,
        })
        links.append({
            "attributes": {},
            "link_type": "EXPOSES",
            "source_node_id": partition,
            "target_node_id": logical,
        })
    return _exact(topology, {
        "boundary_id": "virtual-boundary:control-0",
        "completeness_claimed": False,
        "evidence_source_ids": ["evidence:virtual:control-0"],
        "links": links,
        "nodes": nodes,
        "observed_at": "2026-10-15T00:00:00Z",
        "snapshot_id": "topology:control-0:0:0",
    })


def _objective(observed: dict[str, Any]) -> bool:
    """The objective echo recomputes its own digest; the request match is separate."""
    objective = observed["objective"]
    if type(objective) is not dict or set(objective) != {*_OBJECTIVE_FIELDS, "objective_digest"}:
        return False
    fields = {field: objective[field] for field in _OBJECTIVE_FIELDS}
    if not all(type(value) is str and value for value in fields.values()):
        return False
    if not _DIGEST.fullmatch(fields["object_digest"]) or not _DIGEST.fullmatch(fields["collection_digest"]):
        return False
    return objective["objective_digest"] == _digest({"domain": OBJECTIVE_DOMAIN, **fields})


def _request_bound(observed: dict[str, Any], request: dict[str, Any] | None) -> bool:
    """Compare the objective echo with the request the parent actually sent, when supplied."""
    if request is None:
        return True
    objective = observed["objective"]
    return _exact(
        {field: objective[field] for field in _OBJECTIVE_FIELDS},
        {field: request[field] for field in _OBJECTIVE_FIELDS},
    )


def _workload(objective: dict[str, Any]) -> dict[str, Any]:
    from verifier.hardware.models import WorkloadIdentity

    return WorkloadIdentity(
        workload_id="workload:" + objective["object_id"],
        executable_digest=objective["object_digest"].removeprefix("sha256:"),
    ).to_dict()


def _execution_bound(
    identity: Any,
    objective: dict[str, Any],
    *,
    execution_id: str,
    logical_id: str,
    topology: str,
    submitted_at: str,
) -> bool:
    return _exact(identity, {
        "execution_id": execution_id,
        "workload": _workload(objective),
        "logical_device_ids": [logical_id],
        "topology_snapshot_id": topology,
        "submitted_at": submitted_at,
    })


def _accounting_scope(
    row: Any, *, observation_id: str, execution_id: str, logical_id: str, evidence_source: str
) -> bool:
    return (
        type(row) is dict
        and _exact(row.get("observation_id"), observation_id)
        and _exact(row.get("execution_id"), execution_id)
        and _exact(row.get("device_scope_ids"), [logical_id])
        and _exact(row.get("quantities"), _quantities(evidence_source))
    )


def _signature(envelope: Any, *, key_id: str, root: str) -> bool:
    return (
        type(envelope) is dict
        and set(envelope) == _SIGNATURE_KEYS
        and envelope["algorithm"] == _HMAC
        and envelope["key_id"] == key_id
        and envelope["signed_digest"] == root
        and type(envelope["signature_b64"]) is str
        and bool(envelope["signature_b64"])
    )


def _attestation(attestation: Any) -> bool:
    """Recompute the signed attestation digest and nonce binding; HMAC bytes stay worker-side."""
    from verifier.hardware.attestation import attestation_signed_digest
    from verifier.hardware.models import AttestationEvidence, VerificationState

    if type(attestation) is not dict or set(attestation) != {"challenge", "evidence"}:
        return False
    challenge, evidence = attestation["challenge"], attestation["evidence"]
    if not _exact(challenge, {
        "challenge_id": "challenge-0",
        "nonce_b64": _CHALLENGE_NONCE,
        "issued_at": "2026-10-15T00:00:00Z",
        "expires_at": "2026-10-15T01:00:00Z",
        "verifier_id": "emulated-control-worker",
    }):
        return False
    if type(evidence) is not dict:
        return False
    decoded = AttestationEvidence.from_dict(evidence)
    signature = decoded.signature
    return (
        _exact(evidence, decoded.to_dict())
        and decoded.evidence_id == "attestation:control-0:challenge-0"
        and decoded.subject_identity_id == _DEVICE
        and decoded.challenge_id == challenge["challenge_id"]
        and decoded.nonce_b64 == challenge["nonce_b64"]
        and decoded.issued_at == challenge["issued_at"]
        and decoded.expires_at == challenge["expires_at"]
        and decoded.evidence_source_id == "evidence:virtual:control-0"
        and decoded.verification_state is VerificationState.VERIFIED
        and signature is not None
        and signature.algorithm == _HMAC
        and signature.key_id == _KEY_ID
        and signature.signed_digest == attestation_signed_digest(decoded)
        and type(signature.signature_b64) is str
        and bool(signature.signature_b64)
    )


def _clean_continuity(verified: int) -> dict[str, Any]:
    return {"status": "PASS", "verified_event_count": verified, "errors": [], "gaps": []}


def _verdict(observed: dict[str, Any]) -> bool:
    """Digest-check the worker-side verdict; HMAC authenticity beyond the worker is NOT_ESTABLISHED."""
    verdict = observed["worker_verdict"]
    if type(verdict) is not dict or set(verdict) != {
        "schema_version", "attestation_signature", "continuity", "verdict_digest",
    }:
        return False
    continuity = verdict["continuity"]
    if type(continuity) is not dict or set(continuity) != _CONTINUITY_KEYS:
        return False
    body = {
        "schema_version": verdict["schema_version"],
        "attestation_signature": verdict["attestation_signature"],
        "continuity": continuity,
    }
    return (
        verdict["schema_version"] == VERDICT_SCHEMA
        and verdict["attestation_signature"] == "PASS"
        and _exact(continuity["normal"], _clean_continuity(4))
        and _exact(continuity["feedback_loss"], _clean_continuity(3))
        and _exact(continuity["arbitration"], _clean_continuity(7))
        and _exact(continuity["recovery"], _clean_continuity(7))
        and _exact(continuity["reset"], _clean_continuity(4))
        and _exact(observed["reset"]["success"]["continuity"], continuity["reset"])
        and verdict["verdict_digest"] == _digest(body)
    )


def _anchor_signature(anchor: Any, root: str) -> bool:
    return type(anchor) is dict and _signature(
        anchor.get("signature"), key_id=_ANCHOR_KEY_ID, root=root
    )


def _normal(observed: dict[str, Any]) -> bool:
    """Bind the fresh lifecycle: identity, topology, boot, command, feedback, completion and attestation."""
    normal = observed["normal"]
    if type(normal) is not dict or set(normal) != _NORMAL_KEYS:
        return False
    feedback = normal["feedback"]
    events = normal["events"]
    if type(events) is not list or len(events) != 4 or not _chain(events, _DEVICE):
        return False
    if [event["event_type"] for event in events] != [
        "DEVICE_BOOT", "EXEC_START", "EXEC_OBSERVATION", "EXEC_END",
    ]:
        return False
    boot, begin, sample, finish = events
    if (
        [boot["partition_id"], boot["execution_id"]] != ["", ""]
        or any(
            row["partition_id"] != "partition:control-0:a"
            or row["execution_id"] != "execution-0"
            for row in (begin, sample, finish)
        )
    ):
        return False
    return (
        _exact(normal["descriptor"], {
            "architecture": "reference-emulator",
            "attributes": {"root_of_trust": "TEST_HMAC_FIXTURE"},
            "deployment_class": "emulator",
            "descriptor_id": "descriptor:control-0",
            "device_class": "AI_ASIC",
            "discovery_method": "constructed reference device",
            "family": "VirtualVSTDAccelerator",
            "model": "VirtualVSTDAccelerator",
            "profile_id": "vstd.virtual-firmware-1",
            "vendor": "EMULATED",
        })
        and _exact(normal["command_bindings"], {
            "device_identity_id": _DEVICE,
            "topology_snapshot_id": "topology:control-0:0:0",
            "execution_id": "execution-0",
            "start_event_id": "event:control-0:0:1",
            "feedback_event_id": "event:control-0:0:2",
            "end_event_id": "event:control-0:0:3",
        })
        and _exact(
            normal["trust_boundary"],
            {
                "authentication": "TEST_HMAC_FIXTURE",
                "hmac_verification": "WORKER_SIDE_ONLY",
                "hmac_key_exposed_to_parent": False,
                "hmac_authenticity_beyond_worker": "NOT_ESTABLISHED",
                "command_authority": "NOT_ESTABLISHED",
                "real_world_authority": "NOT_ESTABLISHED",
                "measured_latency": "NOT_ESTABLISHED",
                "physical_effect_claimed": False,
                "physical_stability_claimed": False,
                "physical_attestation_claimed": False,
                "safe_state_claimed": False,
            },
        )
        and _topology(normal["topology"])
        and _exact(normal["start"], {
            "event_id": begin["event_id"],
            "execution_id": "execution-0",
            "started_at": begin["timestamp"],
        })
        and _exact(normal["observation"], {
            "accounting_observation_id": "accounting:execution-0:0",
            "event_id": sample["event_id"],
            "execution_id": "execution-0",
            "observed_at": sample["timestamp"],
        })
        and _exact(normal["end"], {
            "completed_at": finish["timestamp"],
            "event_id": finish["event_id"],
            "execution_id": "execution-0",
            "outcome": "COMPLETED",
            "output_commitments": [],
        })
        and _exact(feedback, {
            "schema_version": "verifier-simulated-actuator-feedback-1",
            "feedback_type": "ComputeAccountingObservation",
            "physical_effect_claimed": False,
            "observation": {
                "device_scope_ids": ["logical:partition:control-0:a"],
                "evidence_source_ids": ["evidence:virtual:control-0"],
                "execution_id": "execution-0",
                "observation_id": "accounting:execution-0:0",
                "observed_at": sample["timestamp"],
                "quantities": _quantities("evidence:virtual:control-0"),
            },
        })
        and _payload(begin, normal["execution_identity"])
        and _payload(sample, feedback["observation"])
        and _payload(finish, {
            "execution_id": "execution-0",
            "outcome": "COMPLETED",
            "output_commitments": [],
        })
        and _execution_bound(
            normal["execution_identity"],
            observed["objective"],
            execution_id="execution-0",
            logical_id="logical:partition:control-0:a",
            topology="topology:control-0:0:0",
            submitted_at="2026-10-15T00:00:01Z",
        )
        and _attestation(normal["attestation"])
    )


def _ordered_response(events: list[dict[str, Any]]) -> bool:
    """Feedback is strictly between submission and completion in the scripted trace."""
    return events[1]["timestamp"] < events[2]["timestamp"] < events[3]["timestamp"]


def _timing_envelope(observed: dict[str, Any]) -> bool:
    normal = observed["normal"]
    return (
        _normal(observed)
        and [row["timestamp"] for row in normal["events"]] == [
            "2026-10-15T00:00:00Z",
            "2026-10-15T00:00:01Z",
            "2026-10-15T00:00:02Z",
            "2026-10-15T00:00:03Z",
        ]
        and _ordered_response(normal["events"])
        and _capacity(observed["capacity"])
    )


def _capacity(capacity: Any) -> bool:
    return _exact(capacity, {
        "exact_limit_ppm": [1_000_000],
        "split_ppm": [400_000, 600_000],
        "over_limit": _refusal(
            "FirmwareContractError", "partition capacity exceeds the physical device"
        ),
    })


def _controls_closed(controls: Any) -> bool:
    return type(controls) is dict and set(controls) == _CONTROL_NAMES


def _reset_success(success: Any) -> bool:
    if type(success) is not dict or set(success) != {
        "anchor", "continuity", "end", "events", "reset_epoch",
    }:
        return False
    events = success["events"]
    if type(events) is not list or len(events) != 4 or not _chain(events, _RESET_DEVICE):
        return False
    if (
        [row["event_type"] for row in events]
        != ["DEVICE_BOOT", "EXEC_START", "EXEC_END", "RESET"]
        or [row["epoch"] for row in events] != [0, 0, 0, 1]
        or [row["execution_id"] for row in events]
        != ["", "execution-reset", "execution-reset", ""]
    ):
        return False
    interrupted = events[2]
    anchor_id = "anchor:control-anchor:" + _RESET_DEVICE + ":0:2"
    anchor = success["anchor"]
    if type(anchor) is not dict or type(anchor.get("signature")) is not dict:
        return False
    return (
        _exact(success["continuity"], _clean_continuity(4))
        and _exact(success["end"], {
            "completed_at": interrupted["timestamp"],
            "event_id": interrupted["event_id"],
            "execution_id": "execution-reset",
            "outcome": "INTERRUPTED",
            "output_commitments": [],
        })
        and _exact(success["reset_epoch"], {
            "boot_id": "reset-1",
            "device_identity_id": _RESET_DEVICE,
            "epoch": 1,
            "external_anchor_id": anchor_id,
            "prior_epoch": 0,
            "prior_rolling_root": interrupted["rolling_root"],
            "reason": "controlled successful reset",
        })
        and _exact(
            {key: value for key, value in anchor.items() if key != "signature"},
            {
                "anchor_id": anchor_id,
                "anchored_at": "2026-10-15T03:00:03Z",
                "device_identity_id": _RESET_DEVICE,
                "epoch": 0,
                "provider_id": "control-anchor",
                "rolling_root": interrupted["rolling_root"],
                "sequence": interrupted["sequence"],
            },
        )
        and _anchor_signature(anchor, interrupted["rolling_root"])
    )


def _intervention(observed: dict[str, Any]) -> bool:
    reset, controls = observed["reset"], observed["controls"]
    return (
        _normal(observed)
        and type(reset) is dict
        and set(reset) == {"anchor_failure", "verification_failure", "success"}
        and _controls_closed(controls)
        and _refused(reset["anchor_failure"], "AnchorError", "controlled anchor failure")
        and _refused(
            reset["verification_failure"],
            "FirmwareContractError",
            "anchor provider could not verify its anchor",
        )
        and _refused(
            controls["active_reconfiguration"],
            "FirmwareContractError",
            "partition configuration cannot change during active execution",
        )
        and _refused(controls["duplicate_execution"], "FirmwareContractError", "execution id replay")
        and _refused(
            controls["duplicate_challenge"],
            "FirmwareContractError",
            "attestation challenge replay",
        )
        and _reset_success(reset["success"])
        and _feedback_loss(observed)
        and _arbitration(observed)
    )


def _feedback_loss(observed: dict[str, Any]) -> bool:
    """A withdrawn feedback path ends INTERRUPTED with no accounting event; late feedback is refused."""
    loss = observed["feedback_loss"]
    if type(loss) is not dict or set(loss) != {"end", "events", "execution", "late_feedback"}:
        return False
    events = loss["events"]
    if type(events) is not list or len(events) != 3 or not _chain(events, _FEEDBACK_DEVICE):
        return False
    identifier = "execution-feedback-loss"
    logical = "logical:partition:feedback-0:a"
    return (
        _exact([row["event_type"] for row in events], ["DEVICE_BOOT", "EXEC_START", "EXEC_END"])
        and _exact([row["execution_id"] for row in events], ["", identifier, identifier])
        and _exact([row["partition_id"] for row in events], ["", "partition:feedback-0:a", "partition:feedback-0:a"])
        and _execution_bound(
            loss["execution"],
            observed["objective"],
            execution_id=identifier,
            logical_id=logical,
            topology="topology:feedback-0:0:0",
            submitted_at="2026-10-15T04:00:01Z",
        )
        and _payload(events[1], loss["execution"])
        and _exact(loss["end"], {
            "completed_at": events[2]["timestamp"],
            "event_id": events[2]["event_id"],
            "execution_id": identifier,
            "outcome": "INTERRUPTED",
            "output_commitments": [],
        })
        and _payload(events[2], {
            "execution_id": identifier,
            "outcome": "INTERRUPTED",
            "output_commitments": [],
        })
        and _refused(
            loss["late_feedback"],
            "FirmwareContractError",
            "cannot account for an execution that is not active",
        )
    )


def _arbitration(observed: dict[str, Any]) -> bool:
    """Two valid live commands on distinct partitions are serialized with per-command feedback scope."""
    arbitration = observed["arbitration"]
    if type(arbitration) is not dict or set(arbitration) != {
        "accounting", "ends", "events", "executions", "observations", "starts",
    }:
        return False
    events = arbitration["events"]
    if type(events) is not list or len(events) != 7 or not _chain(events, _ARBITRATION_DEVICE):
        return False
    rows = {key: arbitration[key] for key in ("accounting", "ends", "executions", "observations", "starts")}
    if not all(type(items) is list and len(items) == 2 for items in rows.values()):
        return False
    first, second = "execution-arb-a", "execution-arb-b"
    part_a, part_b = "partition:arbitration-0:a", "partition:arbitration-0:b"
    logical_a, logical_b = "logical:" + part_a, "logical:" + part_b
    objective = observed["objective"]
    executions, starts = rows["executions"], rows["starts"]
    observations, accounting, ends = rows["observations"], rows["accounting"], rows["ends"]
    return (
        _exact([row["event_type"] for row in events], [
            "DEVICE_BOOT", "EXEC_START", "EXEC_START", "EXEC_OBSERVATION",
            "EXEC_OBSERVATION", "EXEC_END", "EXEC_END",
        ])
        and _exact([row["execution_id"] for row in events], ["", first, second, first, second, second, first])
        and _exact([row["partition_id"] for row in events], ["", part_a, part_b, part_a, part_b, part_b, part_a])
        and _execution_bound(
            executions[0], objective, execution_id=first, logical_id=logical_a,
            topology="topology:arbitration-0:0:0", submitted_at="2026-10-15T05:00:01Z",
        )
        and _execution_bound(
            executions[1], objective, execution_id=second, logical_id=logical_b,
            topology="topology:arbitration-0:0:0", submitted_at="2026-10-15T05:00:02Z",
        )
        and _payload(events[1], executions[0])
        and _payload(events[2], executions[1])
        and _exact(starts[0], {"execution_id": first, "event_id": events[1]["event_id"], "started_at": events[1]["timestamp"]})
        and _exact(starts[1], {"execution_id": second, "event_id": events[2]["event_id"], "started_at": events[2]["timestamp"]})
        and _accounting_scope(
            accounting[0], observation_id="accounting:execution-arb-a:0", execution_id=first,
            logical_id=logical_a, evidence_source="evidence:virtual:arbitration-0",
        )
        and _accounting_scope(
            accounting[1], observation_id="accounting:execution-arb-b:1", execution_id=second,
            logical_id=logical_b, evidence_source="evidence:virtual:arbitration-0",
        )
        and _payload(events[3], accounting[0])
        and _payload(events[4], accounting[1])
        and _exact(observations[0], {
            "execution_id": first,
            "event_id": events[3]["event_id"],
            "accounting_observation_id": "accounting:execution-arb-a:0",
            "observed_at": events[3]["timestamp"],
        })
        and _exact(observations[1], {
            "execution_id": second,
            "event_id": events[4]["event_id"],
            "accounting_observation_id": "accounting:execution-arb-b:1",
            "observed_at": events[4]["timestamp"],
        })
        and _exact(ends[0], {
            "completed_at": events[5]["timestamp"],
            "event_id": events[5]["event_id"],
            "execution_id": second,
            "outcome": "COMPLETED",
            "output_commitments": [],
        })
        and _payload(events[5], {"execution_id": second, "outcome": "COMPLETED", "output_commitments": []})
        and _exact(ends[1], {
            "completed_at": events[6]["timestamp"],
            "event_id": events[6]["event_id"],
            "execution_id": first,
            "outcome": "COMPLETED",
            "output_commitments": [],
        })
        and _payload(events[6], {"execution_id": first, "outcome": "COMPLETED", "output_commitments": []})
    )


def _recovery(observed: dict[str, Any]) -> bool:
    """Interrupted command ends INTERRUPTED, the reset epoch and anchor bind it, and a later command completes."""
    recovery = observed["recovery"]
    if type(recovery) is not dict or set(recovery) != {
        "anchor", "events", "interrupted_end", "interrupted_execution", "recovered_accounting",
        "recovered_end", "recovered_execution", "recovered_observation", "recovered_start", "reset_epoch",
    }:
        return False
    events = recovery["events"]
    if type(events) is not list or len(events) != 7 or not _chain(events, _RECOVERY_DEVICE):
        return False
    interrupted, recovered = "execution-interrupted", "execution-recovered"
    part = "partition:recovery-0:a"
    logical = "logical:" + part
    anchor_id = "anchor:control-anchor:" + _RECOVERY_DEVICE + ":0:2"
    objective = observed["objective"]
    anchor = recovery["anchor"]
    return (
        _exact([row["event_type"] for row in events], [
            "DEVICE_BOOT", "EXEC_START", "EXEC_END", "RESET", "EXEC_START", "EXEC_OBSERVATION", "EXEC_END",
        ])
        and _exact([row["epoch"] for row in events], [0, 0, 0, 1, 1, 1, 1])
        and _exact([row["execution_id"] for row in events], ["", interrupted, interrupted, "", recovered, recovered, recovered])
        and _exact([row["partition_id"] for row in events], ["", part, part, "", part, part, part])
        and _execution_bound(
            recovery["interrupted_execution"], objective, execution_id=interrupted, logical_id=logical,
            topology="topology:recovery-0:0:0", submitted_at="2026-10-15T06:00:01Z",
        )
        and _payload(events[1], recovery["interrupted_execution"])
        and _exact(recovery["interrupted_end"], {
            "completed_at": events[2]["timestamp"],
            "event_id": events[2]["event_id"],
            "execution_id": interrupted,
            "outcome": "INTERRUPTED",
            "output_commitments": [],
        })
        and _payload(events[2], {"execution_id": interrupted, "outcome": "INTERRUPTED", "output_commitments": []})
        and _exact(recovery["reset_epoch"], {
            "device_identity_id": _RECOVERY_DEVICE,
            "epoch": 1,
            "boot_id": _RECOVERY_BOOT,
            "reason": _RECOVERY_REASON,
            "prior_epoch": 0,
            "prior_rolling_root": events[2]["rolling_root"],
            "external_anchor_id": anchor_id,
        })
        and _payload(events[3], {"boot_id": _RECOVERY_BOOT, "reason": _RECOVERY_REASON, "prior_anchor_id": anchor_id})
        and type(anchor) is dict
        and _exact({key: value for key, value in anchor.items() if key != "signature"}, {
            "anchor_id": anchor_id,
            "anchored_at": "2026-10-15T06:00:02Z",
            "device_identity_id": _RECOVERY_DEVICE,
            "epoch": 0,
            "provider_id": "control-anchor",
            "rolling_root": events[2]["rolling_root"],
            "sequence": 2,
        })
        and _anchor_signature(anchor, events[2]["rolling_root"])
        and _execution_bound(
            recovery["recovered_execution"], objective, execution_id=recovered, logical_id=logical,
            topology="topology:recovery-0:1:0", submitted_at="2026-10-15T06:00:03Z",
        )
        and _payload(events[4], recovery["recovered_execution"])
        and _exact(recovery["recovered_start"], {
            "execution_id": recovered,
            "event_id": events[4]["event_id"],
            "started_at": events[4]["timestamp"],
        })
        and _exact(recovery["recovered_observation"], {
            "execution_id": recovered,
            "event_id": events[5]["event_id"],
            "accounting_observation_id": "accounting:execution-recovered:0",
            "observed_at": events[5]["timestamp"],
        })
        and _accounting_scope(
            recovery["recovered_accounting"],
            observation_id="accounting:execution-recovered:0",
            execution_id=recovered,
            logical_id=logical,
            evidence_source="evidence:virtual:recovery-0",
        )
        and _payload(events[5], recovery["recovered_accounting"])
        and _exact(recovery["recovered_end"], {
            "completed_at": events[6]["timestamp"],
            "event_id": events[6]["event_id"],
            "execution_id": recovered,
            "outcome": "COMPLETED",
            "output_commitments": [],
        })
        and _payload(events[6], {"execution_id": recovered, "outcome": "COMPLETED", "output_commitments": []})
    )


def _response(observed: dict[str, Any]) -> bool:
    normal = observed["normal"]
    return (
        _normal(observed)
        and _ordered_response(normal["events"])
        and _capacity(observed["capacity"])
    )


def _interlocks(observed: dict[str, Any]) -> bool:
    controls = observed["controls"]
    expected = {
        "active_reconfiguration": (
            "FirmwareContractError",
            "partition configuration cannot change during active execution",
        ),
        "bad_device": (
            "FirmwareContractError",
            "execution references a logical device outside this boundary",
        ),
        "bad_topology": (
            "FirmwareContractError",
            "execution is not bound to the current topology snapshot",
        ),
        "bad_evidence": (
            "FirmwareContractError",
            "emulator counters must reference the emulator evidence source",
        ),
        "bad_quantity": (
            "FirmwareContractError",
            "execution observation requires at least one quantity",
        ),
        "duplicate_execution": ("FirmwareContractError", "execution id replay"),
        "duplicate_challenge": ("FirmwareContractError", "attestation challenge replay"),
    }
    return (
        _normal(observed)
        and _controls_closed(controls)
        and all(
            _refused(controls[name], exception, message)
            for name, (exception, message) in expected.items()
        )
    )


def _interlocks_and_recovery(observed: dict[str, Any]) -> bool:
    return _interlocks(observed) and _recovery(observed)


_CHECKS = {
    "CONTROLLER-1.1": _normal,
    "CONTROLLER-2.1": _timing_envelope,
    "CONTROLLER-3.1": _intervention,
    "ACTUATOR-1.1": _normal,
    "ACTUATOR-2.1": _response,
    "ACTUATOR-3.1": _interlocks_and_recovery,
}


def check_observations(
    coordinate: str, observed: dict[str, Any], request: dict[str, Any] | None = None
) -> bool:
    """Recheck raw software effects and refusals outside the worker.

    Malformed or missing evidence fails closed as False; only an unregistered
    coordinate raises. Passing the request the parent sent also binds the
    objective echo to it; callers that omit it get the self-consistency check only.
    """
    if coordinate not in _CHECKS:
        raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")
    if type(observed) is not dict or set(observed) != _OBSERVED_KEYS:
        return False
    try:
        return (
            _objective(observed)
            and _request_bound(observed, request)
            and _verdict(observed)
            and _CHECKS[coordinate](observed) is True
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return False


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound

    return execute_bound(snapshot, item, selection)


def evaluate(
    snapshot: Any, item: NamespaceObject, route: dict[str, Any]
) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected

    return evaluate_selected(snapshot, item, route)
