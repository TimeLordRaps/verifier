"""External continuity-anchor interfaces and deterministic local implementations."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Optional, Protocol

from .canonical import canonical_json_bytes, strict_decode
from .continuity import hmac_sign_digest, verify_hmac_signature
from .models import AccountingEvent, ContinuityAnchor


class AnchorError(RuntimeError):
    pass


class AnchorProvider(Protocol):
    provider_id: str

    def anchor(self, event: AccountingEvent, *, anchored_at: str) -> ContinuityAnchor: ...

    def anchor_content(
        self,
        content_id: str,
        content_digest: str,
        *,
        epoch: int,
        sequence: int,
        anchored_at: str,
    ) -> ContinuityAnchor: ...

    def get(self, anchor_id: str) -> Optional[ContinuityAnchor]: ...

    def verify(self, anchor: ContinuityAnchor) -> bool: ...


@dataclass
class LocalAnchorProvider:
    provider_id: str
    key_id: str
    signing_key: bytes

    def __post_init__(self) -> None:
        self._anchors: dict[str, ContinuityAnchor] = {}

    def anchor(self, event: AccountingEvent, *, anchored_at: str) -> ContinuityAnchor:
        return self.anchor_content(
            event.device_identity_id,
            event.rolling_root,
            epoch=event.epoch,
            sequence=event.sequence,
            anchored_at=anchored_at,
        )

    def anchor_content(
        self,
        content_id: str,
        content_digest: str,
        *,
        epoch: int,
        sequence: int,
        anchored_at: str,
    ) -> ContinuityAnchor:
        """Anchor non-device content through the same provider and trust root."""
        anchor_id = f"anchor:{self.provider_id}:{content_id}:{epoch}:{sequence}"
        candidate = ContinuityAnchor(
            anchor_id=anchor_id,
            device_identity_id=content_id,
            epoch=epoch,
            sequence=sequence,
            rolling_root=content_digest,
            anchored_at=anchored_at,
            provider_id=self.provider_id,
            signature=hmac_sign_digest(
                content_digest,
                key_id=self.key_id,
                key=self.signing_key,
            ),
        )
        existing = self._anchors.get(anchor_id)
        if existing is not None and existing != candidate:
            raise AnchorError(f"anchor fork for {anchor_id}")
        self._anchors[anchor_id] = candidate
        return candidate

    def get(self, anchor_id: str) -> Optional[ContinuityAnchor]:
        return self._anchors.get(anchor_id)

    def verify(self, anchor: ContinuityAnchor) -> bool:
        return anchor.provider_id == self.provider_id and verify_hmac_signature(
            anchor.signature, self.signing_key
        )


class FileAnchorProvider(LocalAnchorProvider):
    """Append-only JSONL anchor log with duplicate/fork rejection."""

    def __init__(self, path: Path, *, provider_id: str, key_id: str, signing_key: bytes) -> None:
        super().__init__(provider_id=provider_id, key_id=key_id, signing_key=signing_key)
        self.path = path
        if path.exists():
            self._load()

    def _load(self) -> None:
        for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                payload = json.loads(line)
                anchor = strict_decode(ContinuityAnchor, payload)
            except (json.JSONDecodeError, ValueError) as exc:
                raise AnchorError(f"malformed anchor log line {line_number}: {exc}") from exc
            existing = self._anchors.get(anchor.anchor_id)
            if existing is not None and existing != anchor:
                raise AnchorError(f"anchor fork in file for {anchor.anchor_id}")
            self._anchors[anchor.anchor_id] = anchor

    def anchor_content(
        self,
        content_id: str,
        content_digest: str,
        *,
        epoch: int,
        sequence: int,
        anchored_at: str,
    ) -> ContinuityAnchor:
        anchor = super().anchor_content(
            content_id,
            content_digest,
            epoch=epoch,
            sequence=sequence,
            anchored_at=anchored_at,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing_lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        if not any(json.loads(line).get("anchor_id") == anchor.anchor_id for line in existing_lines if line):
            with self.path.open("ab") as handle:
                handle.write(canonical_json_bytes(anchor) + b"\n")
        return anchor
