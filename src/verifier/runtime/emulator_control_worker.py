"""Private simulated control worker for Verifier Standard (VSTD).

Terminology: hash-based message authentication code (HMAC).

Only the fixed installed reference emulator runs. It receives no command,
module, device, key or external resource from the caller; the request carries
only an objective identity (object id, object and collection digests, nonce).
Raw observations, including worker-side HMAC verdicts, are returned to the
parent oracle. The parent recomputes digests and rolling roots but holds no
fixture key, so it does not verify HMAC bytes itself and cannot issue package
PASS. Secure Hash Algorithm 256-bit (SHA-256) and hash-based message
authentication code (HMAC) values use deterministic test fixtures only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Callable


OBJECTIVE_DOMAIN = "verifier-emulated-control-objective-1"
VERDICT_SCHEMA = "verifier-emulated-control-worker-verdict-1"
_OBJECT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DEVICE_KEY = b"vstd-emulated-control-device-key"
_ANCHOR_KEY = b"vstd-emulated-control-anchor-key"


def source_pins() -> dict[str, str]:
    """Bind all executable package sources and interpreted polish text."""
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(
        root / name
        for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md")
    )
    return {
        path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def continuity_verdict(record: Any, keys: dict[str, bytes]) -> dict[str, Any]:
    """HMAC continuity verification where the fixture keys are held: worker-side only."""
    from verifier.hardware.continuity import verify_continuity

    result = verify_continuity(record, key_resolver=keys.get)
    return {
        "status": result.status.value,
        "verified_event_count": result.verified_event_count,
        "errors": list(result.errors),
        "gaps": [row.to_dict() for row in result.gaps],
    }


def attestation_verdict(evidence: Any, key: bytes) -> str:
    """PASS only when the HMAC envelope verifies over the recomputed signed digest."""
    from verifier.hardware.attestation import attestation_signed_digest
    from verifier.hardware.continuity import verify_hmac_signature

    signature = evidence.signature
    if signature is None or signature.signed_digest != attestation_signed_digest(evidence):
        return "FAIL"
    return "PASS" if verify_hmac_signature(signature, key) else "FAIL"


def observe(request: dict[str, str]) -> dict[str, Any]:
    """Exercise public emulator operations and controlled boundary refusals."""
    from verifier.hardware.anchors import AnchorError, LocalAnchorProvider
    from verifier.hardware.canonical import canonical_digest
    from verifier.hardware.emulator import VirtualVSTDAccelerator
    from verifier.hardware.models import (
        AccountingExactness,
        AccountingMethod,
        AccountingQuantity,
        ExecutionIdentity,
        ExecutionOutcome,
        WorkloadIdentity,
    )

    device_key = _DEVICE_KEY
    anchor_key = _ANCHOR_KEY
    device_keys = {"vstd3-virtual-device-key": device_key, "control-anchor-key": anchor_key}
    object_hex = request["object_digest"].removeprefix("sha256:")
    objective_fields = {
        field: request[field] for field in ("object_id", "object_digest", "collection_digest", "nonce")
    }
    objective = {
        **objective_fields,
        "objective_digest": canonical_digest({"domain": OBJECTIVE_DOMAIN, **objective_fields}),
    }

    def state(device: VirtualVSTDAccelerator) -> dict[str, Any]:
        topology = device.current_topology_snapshot_id if device._epoch >= 0 else None
        return {
            "record": device.continuity_record().to_dict(),
            "active": sorted(device._active),
            "ends": [row.to_dict() for row in device._ends],
            "topology": topology,
            "partitions": [row.to_dict() for row in device._partitions],
            "logical": [row.to_dict() for row in device._logical],
        }

    def attempt(device: VirtualVSTDAccelerator, operation: Callable[[], Any]) -> dict[str, Any]:
        before = state(device)
        try:
            operation()
        except Exception as exc:
            return {
                "returned": False,
                "exception": type(exc).__name__,
                "message": str(exc),
                "unchanged": state(device) == before,
            }
        return {"returned": True, "exception": None, "message": None, "unchanged": state(device) == before}

    def execution(
        device: VirtualVSTDAccelerator,
        identifier: str,
        *,
        logical_id: str = "logical:partition:control-0:a",
        topology: str | None = None,
        submitted_at: str = "2026-10-15T00:00:01Z",
    ) -> ExecutionIdentity:
        return ExecutionIdentity(
            identifier,
            WorkloadIdentity("workload:" + request["object_id"], executable_digest=object_hex),
            (logical_id,),
            topology or device.current_topology_snapshot_id,
            submitted_at,
        )

    def quantity(device: VirtualVSTDAccelerator) -> AccountingQuantity:
        return AccountingQuantity(
            "issued_operations",
            "42",
            "operations",
            AccountingMethod.FIRMWARE_COUNTER,
            device.evidence_source_id,
            "reference emulator command issue counter",
            AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
        )

    device = VirtualVSTDAccelerator("control-0", "1.0.0", device_key)
    device.configure_partitions(
        (
            ("partition:control-0:a", "virtual-slice", 400_000),
            ("partition:control-0:b", "virtual-slice", 600_000),
        )
    )
    device.boot(boot_id="boot-0", timestamp="2026-10-15T00:00:00Z")
    topology = device.topology_snapshot(observed_at="2026-10-15T00:00:00Z")
    challenge = device.issue_challenge(
        challenge_id="challenge-0",
        nonce=b"control-nonce-0001",
        issued_at="2026-10-15T00:00:00Z",
        expires_at="2026-10-15T01:00:00Z",
        verifier_id="emulated-control-worker",
    )
    evidence = device.attest(challenge)
    job = execution(device, "execution-0")
    start = device.submit_execution(job, timestamp="2026-10-15T00:00:01Z")
    observation = device.observe_execution(
        job.execution_id,
        (quantity(device),),
        timestamp="2026-10-15T00:00:02Z",
    )
    end = device.complete_execution(job.execution_id, timestamp="2026-10-15T00:00:03Z")
    normal_record = device.continuity_record()
    events = [row.to_dict() for row in normal_record.events]
    accounting = device._accounting[0].to_dict()
    normal = {
        "descriptor": device.descriptor.to_dict(),
        "topology": topology.to_dict(),
        "start": start.to_dict(),
        "observation": observation.to_dict(),
        "end": end.to_dict(),
        "events": events,
        "command_bindings": {
            "device_identity_id": device.physical_identity_id,
            "topology_snapshot_id": job.topology_snapshot_id,
            "execution_id": job.execution_id,
            "start_event_id": start.event_id,
            "feedback_event_id": observation.event_id,
            "end_event_id": end.event_id,
        },
        "execution_identity": job.to_dict(),
        "attestation": {"challenge": challenge.to_dict(), "evidence": evidence.to_dict()},
        "feedback": {
            "schema_version": "verifier-simulated-actuator-feedback-1",
            "feedback_type": "ComputeAccountingObservation",
            "physical_effect_claimed": False,
            "observation": accounting,
        },
        "trust_boundary": {
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
    }

    at_limit = VirtualVSTDAccelerator("capacity-limit", "1.0.0", device_key)
    at_limit.configure_partitions((("partition:limit", "virtual-slice", 1_000_000),))
    over_limit = VirtualVSTDAccelerator("capacity-over", "1.0.0", device_key)
    capacity = {
        "split_ppm": [row.capacity_fraction_ppm for row in device._partitions],
        "exact_limit_ppm": [row.capacity_fraction_ppm for row in at_limit._partitions],
        "over_limit": attempt(
            over_limit,
            lambda: over_limit.configure_partitions(
                (
                    ("partition:over:a", "virtual-slice", 600_000),
                    ("partition:over:b", "virtual-slice", 400_001),
                )
            ),
        ),
    }

    control_device = VirtualVSTDAccelerator("control-0", "1.0.0", device_key)
    control_device.configure_partitions(
        (("partition:control-0:a", "virtual-slice", 1_000_000),)
    )
    control_device.boot(boot_id="control-boot", timestamp="2026-10-15T02:00:00Z")
    active = execution(control_device, "execution-control", submitted_at="2026-10-15T02:00:01Z")
    control_device.submit_execution(active, timestamp="2026-10-15T02:00:01Z")
    controls = {
        "active_reconfiguration": attempt(
            control_device,
            lambda: control_device.configure_partitions(
                (("partition:control-0:b", "virtual-slice", 1_000_000),),
                timestamp="2026-10-15T02:00:02Z",
            ),
        ),
        "bad_device": attempt(
            control_device,
            lambda: control_device.submit_execution(
                execution(
                    control_device,
                    "execution-bad-device",
                    logical_id="logical:partition:unknown",
                ),
                timestamp="2026-10-15T02:00:02Z",
            ),
        ),
        "bad_topology": attempt(
            control_device,
            lambda: control_device.submit_execution(
                execution(
                    control_device,
                    "execution-bad-topology",
                    topology="topology:control-0:stale",
                ),
                timestamp="2026-10-15T02:00:02Z",
            ),
        ),
        "bad_evidence": attempt(
            control_device,
            lambda: control_device.observe_execution(
                active.execution_id,
                (
                    AccountingQuantity(
                        "issued_operations",
                        "42",
                        "operations",
                        AccountingMethod.FIRMWARE_COUNTER,
                        "evidence:outside-boundary",
                        "reference emulator command issue counter",
                        AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
                    ),
                ),
                timestamp="2026-10-15T02:00:02Z",
            ),
        ),
        "bad_quantity": attempt(
            control_device,
            lambda: control_device.observe_execution(
                active.execution_id, (), timestamp="2026-10-15T02:00:02Z"
            ),
        ),
    }
    control_device.complete_execution(active.execution_id, timestamp="2026-10-15T02:00:03Z")
    controls["duplicate_execution"] = attempt(
        control_device,
        lambda: control_device.submit_execution(
            active, timestamp="2026-10-15T02:00:04Z"
        ),
    )
    first_challenge = control_device.issue_challenge(
        challenge_id="challenge-control",
        nonce=b"control-nonce-0002",
        issued_at="2026-10-15T02:00:04Z",
        expires_at="2026-10-15T03:00:00Z",
        verifier_id="emulated-control-worker",
    )
    controls["duplicate_challenge"] = attempt(
        control_device,
        lambda: control_device.issue_challenge(
            challenge_id=first_challenge.challenge_id,
            nonce=b"control-nonce-0003",
            issued_at="2026-10-15T02:00:05Z",
            expires_at="2026-10-15T03:00:00Z",
            verifier_id="emulated-control-worker",
        ),
    )

    reset_device = VirtualVSTDAccelerator("reset-0", "1.0.0", device_key)
    reset_device.configure_partitions((("partition:reset-0:a", "virtual-slice", 1_000_000),))
    reset_device.boot(boot_id="reset-boot", timestamp="2026-10-15T03:00:00Z")
    reset_job = ExecutionIdentity(
        "execution-reset",
        WorkloadIdentity("workload:reset", hashlib.sha256(b"reset").hexdigest()),
        ("logical:partition:reset-0:a",),
        reset_device.current_topology_snapshot_id,
        "2026-10-15T03:00:01Z",
    )
    reset_device.submit_execution(reset_job, timestamp="2026-10-15T03:00:01Z")

    class RefusingAnchor(LocalAnchorProvider):
        mode = "anchor"

        def anchor(self, event, *, anchored_at):
            if self.mode == "anchor":
                raise AnchorError("controlled anchor failure")
            return super().anchor(event, anchored_at=anchored_at)

        def verify(self, anchor):
            return self.mode != "verify" and super().verify(anchor)

    refusing = RefusingAnchor("refusing-anchor", "refusing-key", anchor_key)
    anchor_failure = attempt(
        reset_device,
        lambda: reset_device.reset(
            boot_id="refused-anchor",
            reason="controlled anchor failure",
            timestamp="2026-10-15T03:00:02Z",
            anchor_provider=refusing,
        ),
    )
    refusing.mode = "verify"
    verification_failure = attempt(
        reset_device,
        lambda: reset_device.reset(
            boot_id="refused-verification",
            reason="controlled verification failure",
            timestamp="2026-10-15T03:00:02Z",
            anchor_provider=refusing,
        ),
    )
    anchor = LocalAnchorProvider("control-anchor", "control-anchor-key", anchor_key)
    reset_device.reset(
        boot_id="reset-1",
        reason="controlled successful reset",
        timestamp="2026-10-15T03:00:03Z",
        anchor_provider=anchor,
    )
    reset_record = reset_device.continuity_record()
    reset_continuity = continuity_verdict(reset_record, device_keys)
    reset = {
        "anchor_failure": anchor_failure,
        "verification_failure": verification_failure,
        "success": {
            "events": [row.to_dict() for row in reset_record.events],
            "end": reset_device._ends[-1].to_dict(),
            "reset_epoch": reset_record.reset_epochs[-1].to_dict(),
            "anchor": reset_record.anchors[-1].to_dict(),
            "continuity": reset_continuity,
        },
    }

    # Feedback withdrawal: the command is never accounted for, ends INTERRUPTED,
    # and late feedback for it is refused without changing simulated state.
    feedback = VirtualVSTDAccelerator("feedback-0", "1.0.0", device_key)
    feedback.configure_partitions((("partition:feedback-0:a", "virtual-slice", 1_000_000),))
    feedback.boot(boot_id="feedback-boot", timestamp="2026-10-15T04:00:00Z")
    withdrawn = execution(
        feedback,
        "execution-feedback-loss",
        logical_id="logical:partition:feedback-0:a",
        submitted_at="2026-10-15T04:00:01Z",
    )
    feedback.submit_execution(withdrawn, timestamp="2026-10-15T04:00:01Z")
    withdrawn_end = feedback.complete_execution(
        withdrawn.execution_id,
        timestamp="2026-10-15T04:00:02Z",
        outcome=ExecutionOutcome.INTERRUPTED,
    )
    late_feedback = attempt(
        feedback,
        lambda: feedback.observe_execution(
            withdrawn.execution_id,
            (quantity(feedback),),
            timestamp="2026-10-15T04:00:03Z",
        ),
    )
    feedback_loss = {
        "execution": withdrawn.to_dict(),
        "end": withdrawn_end.to_dict(),
        "events": [row.to_dict() for row in feedback.continuity_record().events],
        "late_feedback": late_feedback,
    }

    # Competing live commands: both valid on distinct partitions, each with its
    # own feedback scope; the device serializes them into one rolling chain.
    arbiter = VirtualVSTDAccelerator("arbitration-0", "1.0.0", device_key)
    arbiter.configure_partitions(
        (
            ("partition:arbitration-0:a", "virtual-slice", 400_000),
            ("partition:arbitration-0:b", "virtual-slice", 600_000),
        )
    )
    arbiter.boot(boot_id="arbitration-boot", timestamp="2026-10-15T05:00:00Z")
    first = execution(
        arbiter,
        "execution-arb-a",
        logical_id="logical:partition:arbitration-0:a",
        submitted_at="2026-10-15T05:00:01Z",
    )
    second = execution(
        arbiter,
        "execution-arb-b",
        logical_id="logical:partition:arbitration-0:b",
        submitted_at="2026-10-15T05:00:02Z",
    )
    first_start = arbiter.submit_execution(first, timestamp="2026-10-15T05:00:01Z")
    second_start = arbiter.submit_execution(second, timestamp="2026-10-15T05:00:02Z")
    first_observation = arbiter.observe_execution(
        first.execution_id, (quantity(arbiter),), timestamp="2026-10-15T05:00:03Z"
    )
    second_observation = arbiter.observe_execution(
        second.execution_id, (quantity(arbiter),), timestamp="2026-10-15T05:00:04Z"
    )
    second_end = arbiter.complete_execution(second.execution_id, timestamp="2026-10-15T05:00:05Z")
    first_end = arbiter.complete_execution(first.execution_id, timestamp="2026-10-15T05:00:06Z")
    arbitration = {
        "executions": [first.to_dict(), second.to_dict()],
        "starts": [first_start.to_dict(), second_start.to_dict()],
        "observations": [first_observation.to_dict(), second_observation.to_dict()],
        "accounting": [row.to_dict() for row in arbiter._accounting],
        "ends": [second_end.to_dict(), first_end.to_dict()],
        "events": [row.to_dict() for row in arbiter.continuity_record().events],
    }

    # Actuator reset and recovery: an interrupted command is ended, the new epoch
    # is anchored to that end, and a later command completes on the new topology.
    recovery_device = VirtualVSTDAccelerator("recovery-0", "1.0.0", device_key)
    recovery_device.configure_partitions((("partition:recovery-0:a", "virtual-slice", 1_000_000),))
    recovery_device.boot(boot_id="recovery-boot", timestamp="2026-10-15T06:00:00Z")
    interrupted = execution(
        recovery_device,
        "execution-interrupted",
        logical_id="logical:partition:recovery-0:a",
        submitted_at="2026-10-15T06:00:01Z",
    )
    recovery_device.submit_execution(interrupted, timestamp="2026-10-15T06:00:01Z")
    recovery_anchor = LocalAnchorProvider("control-anchor", "control-anchor-key", anchor_key)
    recovery_device.reset(
        boot_id="recovery-1",
        reason="controlled actuator recovery after interrupted command",
        timestamp="2026-10-15T06:00:02Z",
        anchor_provider=recovery_anchor,
    )
    recovered = execution(
        recovery_device,
        "execution-recovered",
        logical_id="logical:partition:recovery-0:a",
        submitted_at="2026-10-15T06:00:03Z",
    )
    recovered_start = recovery_device.submit_execution(recovered, timestamp="2026-10-15T06:00:03Z")
    recovered_observation = recovery_device.observe_execution(
        recovered.execution_id, (quantity(recovery_device),), timestamp="2026-10-15T06:00:04Z"
    )
    recovered_end = recovery_device.complete_execution(
        recovered.execution_id, timestamp="2026-10-15T06:00:05Z"
    )
    recovery_record = recovery_device.continuity_record()
    recovery = {
        "interrupted_execution": interrupted.to_dict(),
        "interrupted_end": recovery_device._ends[0].to_dict(),
        "reset_epoch": recovery_record.reset_epochs[-1].to_dict(),
        "anchor": recovery_record.anchors[-1].to_dict(),
        "recovered_execution": recovered.to_dict(),
        "recovered_start": recovered_start.to_dict(),
        "recovered_observation": recovered_observation.to_dict(),
        "recovered_accounting": recovery_device._accounting[-1].to_dict(),
        "recovered_end": recovered_end.to_dict(),
        "events": [row.to_dict() for row in recovery_record.events],
    }

    checks = {
        "normal": continuity_verdict(normal_record, device_keys),
        "feedback_loss": continuity_verdict(feedback.continuity_record(), device_keys),
        "arbitration": continuity_verdict(arbiter.continuity_record(), device_keys),
        "recovery": continuity_verdict(recovery_record, device_keys),
        "reset": reset_continuity,
    }
    verdict_body = {
        "schema_version": VERDICT_SCHEMA,
        "attestation_signature": attestation_verdict(evidence, device_key),
        "continuity": checks,
    }
    return {
        "objective": objective,
        "normal": normal,
        "capacity": capacity,
        "controls": controls,
        "reset": reset,
        "feedback_loss": feedback_loss,
        "arbitration": arbitration,
        "recovery": recovery,
        "worker_verdict": {**verdict_body, "verdict_digest": canonical_digest(verdict_body)},
    }


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (
        type(request) is not dict
        or set(request)
        != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}
        or request["schema_version"] != "verifier-emulated-control-request-1"
        or any(
            type(value) is not str or not 1 <= len(value) <= 256
            for value in request.values()
        )
        or not _OBJECT_DIGEST.fullmatch(request["object_digest"])
        or not _OBJECT_DIGEST.fullmatch(request["collection_digest"])
    ):
        raise ValueError("closed bounded emulated-control request required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-emulated-control-check-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        observations = observe(request)
    if before != source_pins():
        raise ValueError("worker source changed")
    sys.stdout.write(
        json.dumps(
            {
                "schema_version": "verifier-emulated-control-observations-2",
                "request": request,
                "source_pins": before,
                "observations": observations,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
