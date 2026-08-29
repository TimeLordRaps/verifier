"""Terminology: hash-based message authentication code (HMAC);
International Organization for Standardization (ISO); Verifier Standard (VSTD).

Authenticated event sequencing and reset-epoch verification for VSTD 3."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
from typing import Callable, Mapping, Optional

from .canonical import canonical_digest
from .models import (
    AccountingEvent,
    ClaimStatus,
    ContinuityAnchor,
    ContinuityRecord,
    EventType,
    EvidenceGap,
    ResetEpoch,
    SignatureEnvelope,
)


CONTINUITY_DOMAIN = "VSTD3-CONTINUITY-1"
TEST_SIGNATURE_ALGORITHM = "HMAC-SHA256-TEST-ONLY"


def genesis_root(reset: ResetEpoch) -> str:
    return canonical_digest(
        {
            "domain": f"{CONTINUITY_DOMAIN}:GENESIS",
            "device_identity_id": reset.device_identity_id,
            "epoch": reset.epoch,
            "boot_id": reset.boot_id,
            "prior_epoch": reset.prior_epoch,
            "prior_rolling_root": reset.prior_rolling_root,
            "external_anchor_id": reset.external_anchor_id,
        }
    )


def next_rolling_root(
    previous_root: str,
    *,
    event_type: EventType,
    device_identity_id: str,
    partition_id: str,
    execution_id: str,
    epoch: int,
    sequence: int,
    timestamp: str,
    event_payload_digest: str,
) -> str:
    return canonical_digest(
        {
            "domain": f"{CONTINUITY_DOMAIN}:EVENT",
            "previous_root": previous_root,
            "event_type": event_type.value,
            "device_identity_id": device_identity_id,
            "partition_id": partition_id,
            "execution_id": execution_id,
            "epoch": epoch,
            "sequence": sequence,
            "timestamp": timestamp,
            "event_payload_digest": event_payload_digest,
        }
    )


def hmac_sign_digest(digest: str, *, key_id: str, key: bytes) -> SignatureEnvelope:
    signature = hmac.new(key, digest.encode("ascii"), hashlib.sha256).digest()
    return SignatureEnvelope(
        algorithm=TEST_SIGNATURE_ALGORITHM,
        key_id=key_id,
        signed_digest=digest,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_hmac_signature(envelope: SignatureEnvelope, key: bytes) -> bool:
    if envelope.algorithm != TEST_SIGNATURE_ALGORITHM:
        return False
    try:
        observed = base64.b64decode(envelope.signature_b64, validate=True)
    except ValueError:
        return False
    expected = hmac.new(key, envelope.signed_digest.encode("ascii"), hashlib.sha256).digest()
    return hmac.compare_digest(observed, expected)


def build_accounting_event(
    *,
    event_id: str,
    event_type: EventType,
    device_identity_id: str,
    partition_id: str,
    execution_id: str,
    epoch: int,
    sequence: int,
    timestamp: str,
    payload: Mapping[str, object],
    previous_root: str,
    key_id: str,
    signing_key: bytes,
) -> AccountingEvent:
    payload_digest = canonical_digest(payload)
    root = next_rolling_root(
        previous_root,
        event_type=event_type,
        device_identity_id=device_identity_id,
        partition_id=partition_id,
        execution_id=execution_id,
        epoch=epoch,
        sequence=sequence,
        timestamp=timestamp,
        event_payload_digest=payload_digest,
    )
    return AccountingEvent(
        event_id=event_id,
        event_type=event_type,
        device_identity_id=device_identity_id,
        partition_id=partition_id,
        execution_id=execution_id,
        epoch=epoch,
        sequence=sequence,
        timestamp=timestamp,
        event_payload_digest=payload_digest,
        previous_root=previous_root,
        rolling_root=root,
        signature=hmac_sign_digest(root, key_id=key_id, key=signing_key),
    )


@dataclass(frozen=True)
class ContinuityVerification:
    status: ClaimStatus
    verified_event_count: int
    errors: tuple[str, ...]
    gaps: tuple[EvidenceGap, ...]
    first_anchor_id: str
    last_anchor_id: str


KeyResolver = Callable[[str], Optional[bytes]]


def verify_continuity(
    record: ContinuityRecord,
    *,
    key_resolver: Optional[KeyResolver] = None,
) -> ContinuityVerification:
    errors: list[str] = []
    gaps: list[EvidenceGap] = []
    reset_by_epoch: dict[int, ResetEpoch] = {}
    for reset in record.reset_epochs:
        if reset.device_identity_id != record.device_identity_id:
            errors.append(f"reset epoch {reset.epoch} is for the wrong device")
        if reset.epoch in reset_by_epoch:
            errors.append(f"duplicate reset epoch {reset.epoch}")
        reset_by_epoch[reset.epoch] = reset

    seen_event_ids: set[str] = set()
    seen_positions: dict[tuple[int, int], str] = {}
    last_by_epoch: dict[int, AccountingEvent] = {}
    last_time_by_epoch: dict[int, datetime] = {}
    signatures_unverified = False
    verified = 0

    for index, event in enumerate(record.events):
        if event.device_identity_id != record.device_identity_id:
            errors.append(f"event {event.event_id} is for the wrong device")
        if event.event_id in seen_event_ids:
            errors.append(f"duplicate event id {event.event_id}")
        seen_event_ids.add(event.event_id)
        event_position = (event.epoch, event.sequence)
        existing_root = seen_positions.get(event_position)
        if existing_root is not None:
            if existing_root != event.rolling_root:
                errors.append(f"fork at epoch {event.epoch} sequence {event.sequence}")
            else:
                errors.append(f"replayed event at epoch {event.epoch} sequence {event.sequence}")
        seen_positions[event_position] = event.rolling_root

        reset_record = reset_by_epoch.get(event.epoch)
        if reset_record is None:
            errors.append(f"event {event.event_id} references undeclared reset epoch {event.epoch}")
            continue
        try:
            event_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"event {event.event_id} has an invalid ISO-8601 timestamp")
            event_time = None
        if event_time is not None:
            if event_time.tzinfo is None:
                errors.append(f"event {event.event_id} timestamp has no timezone")
            else:
                prior_time = last_time_by_epoch.get(event.epoch)
                if prior_time is not None and event_time < prior_time:
                    errors.append(f"event {event.event_id} timestamp rolled backward within its epoch")
                last_time_by_epoch[event.epoch] = event_time
        previous = last_by_epoch.get(event.epoch)
        if previous is None:
            if event.sequence != 0:
                gaps.append(
                    EvidenceGap(
                        gap_id=f"gap:{record.device_identity_id}:{event.epoch}:0-{event.sequence - 1}",
                        gap_type="MISSING_PREFIX",
                        subject_id=record.device_identity_id,
                        explanation="first observed event in an epoch did not start at sequence zero",
                        first_sequence=0,
                        last_sequence=event.sequence - 1,
                    )
                )
            expected_previous = genesis_root(reset_record)
            if event.event_type not in {EventType.DEVICE_BOOT, EventType.EPOCH_START, EventType.RESET}:
                errors.append(f"epoch {event.epoch} does not start with a boot/reset event")
        else:
            expected_sequence = previous.sequence + 1
            if event.sequence != expected_sequence:
                if event.sequence > expected_sequence:
                    gaps.append(
                        EvidenceGap(
                            gap_id=(
                                f"gap:{record.device_identity_id}:{event.epoch}:"
                                f"{expected_sequence}-{event.sequence - 1}"
                            ),
                            gap_type="MISSING_EVENT",
                            subject_id=record.device_identity_id,
                            explanation="one or more authenticated accounting events are absent",
                            first_sequence=expected_sequence,
                            last_sequence=event.sequence - 1,
                        )
                    )
                else:
                    errors.append(
                        f"sequence rollback in epoch {event.epoch}: {event.sequence} after {previous.sequence}"
                    )
            expected_previous = previous.rolling_root
        if event.previous_root != expected_previous:
            errors.append(f"event {event.event_id} has the wrong predecessor root")
        expected_root = next_rolling_root(
            event.previous_root,
            event_type=event.event_type,
            device_identity_id=event.device_identity_id,
            partition_id=event.partition_id,
            execution_id=event.execution_id,
            epoch=event.epoch,
            sequence=event.sequence,
            timestamp=event.timestamp,
            event_payload_digest=event.event_payload_digest,
        )
        if event.rolling_root != expected_root:
            errors.append(f"event {event.event_id} has an invalid rolling root")
        if event.signature is None:
            signatures_unverified = True
        elif event.signature.signed_digest != event.rolling_root:
            errors.append(f"event {event.event_id} signature is bound to the wrong digest")
        elif key_resolver is None:
            signatures_unverified = True
        else:
            key = key_resolver(event.signature.key_id)
            if key is None:
                signatures_unverified = True
            elif not verify_hmac_signature(event.signature, key):
                errors.append(f"event {event.event_id} signature verification failed")
            else:
                verified += 1
        last_by_epoch[event.epoch] = event
        if index and record.events[index - 1].epoch > event.epoch:
            errors.append("events are reordered across reset epochs")

    ordered_epochs = sorted(reset_by_epoch)
    for epoch_index, epoch in enumerate(ordered_epochs):
        reset_record = reset_by_epoch[epoch]
        if epoch_index == 0:
            if reset_record.prior_epoch is not None or reset_record.prior_rolling_root:
                errors.append("first reset epoch must not invent prior continuity")
            continue
        prior_epoch = ordered_epochs[epoch_index - 1]
        prior_last = last_by_epoch.get(prior_epoch)
        if reset_record.prior_epoch != prior_epoch:
            errors.append(f"reset epoch {epoch} does not name prior epoch {prior_epoch}")
        if prior_last is None:
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap:{record.device_identity_id}:reset:{epoch}",
                    gap_type="RESET_WITHOUT_PRIOR_HISTORY",
                    subject_id=record.device_identity_id,
                    explanation="reset epoch cannot be chained to an observed prior event",
                )
            )
        elif reset_record.prior_rolling_root != prior_last.rolling_root:
            errors.append(f"reset epoch {epoch} is not chained to the prior rolling root")

    anchor_ids: list[str] = []
    anchor_by_id: dict[str, ContinuityAnchor] = {}
    events_by_position = {(event.epoch, event.sequence): event for event in record.events}
    for anchor in record.anchors:
        anchor_ids.append(anchor.anchor_id)
        if anchor.anchor_id in anchor_by_id:
            errors.append(f"duplicate anchor id {anchor.anchor_id}")
        anchor_by_id[anchor.anchor_id] = anchor
        if anchor.device_identity_id != record.device_identity_id:
            errors.append(f"anchor {anchor.anchor_id} is for the wrong device")
            continue
        anchor_event = events_by_position.get((anchor.epoch, anchor.sequence))
        if anchor_event is None:
            errors.append(f"anchor {anchor.anchor_id} references a missing event")
        elif anchor_event.rolling_root != anchor.rolling_root:
            errors.append(f"anchor {anchor.anchor_id} disagrees with the event rolling root")
        if anchor.signature.signed_digest != anchor.rolling_root:
            errors.append(f"anchor {anchor.anchor_id} signature is bound to the wrong digest")
        elif key_resolver is None:
            signatures_unverified = True
        else:
            key = key_resolver(anchor.signature.key_id)
            if key is None:
                signatures_unverified = True
            elif not verify_hmac_signature(anchor.signature, key):
                errors.append(f"anchor {anchor.anchor_id} signature verification failed")

    for epoch in ordered_epochs[1:]:
        reset_record = reset_by_epoch[epoch]
        if not reset_record.external_anchor_id:
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap:{record.device_identity_id}:reset-anchor:{epoch}",
                    gap_type="RESET_WITHOUT_EXTERNAL_ANCHOR",
                    subject_id=record.device_identity_id,
                    explanation="reset epoch is chained locally but lacks an external prior-state anchor",
                )
            )
            continue
        reset_anchor = anchor_by_id.get(reset_record.external_anchor_id)
        if reset_anchor is None:
            errors.append(f"reset epoch {epoch} references a missing external anchor")
        elif reset_anchor.rolling_root != reset_record.prior_rolling_root:
            errors.append(f"reset epoch {epoch} external anchor does not bind the prior rolling root")

    if errors:
        status = ClaimStatus.FAIL
    elif gaps or signatures_unverified or not record.events:
        status = ClaimStatus.UNKNOWN
    else:
        status = ClaimStatus.PASS
    return ContinuityVerification(
        status=status,
        verified_event_count=verified,
        errors=tuple(errors),
        gaps=tuple(gaps),
        first_anchor_id=anchor_ids[0] if anchor_ids else "",
        last_anchor_id=anchor_ids[-1] if anchor_ids else "",
    )
