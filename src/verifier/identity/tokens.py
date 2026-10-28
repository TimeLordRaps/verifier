"""Terminology: JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Token data models and canonical cryptographic operations for zero-identity actors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Final, Literal

BIRTH_TOKEN_SCHEMA: Final[str] = "verifier-birth-token-1"
AGING_TOKEN_SCHEMA: Final[str] = "verifier-aging-token-1"
LIFETIME_TOKEN_SCHEMA: Final[str] = "verifier-lifetime-token-1"


def canonical_token_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize dictionary to deterministic UTF-8 canonical JSON bytes."""
    filtered = {k: v for k, v in payload.items() if v is not None and not k.endswith("signature_base64url")}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_birth_commitment(genesis_key_digest: str, birth_epoch: int, salt: str) -> str:
    """Compute commitment C = SHA-256(genesis_key_digest || epoch || salt)."""
    digest = hashlib.sha256(f"{genesis_key_digest}:{birth_epoch}:{salt}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def advance_aging_accumulator(prior_accumulator_digest: str, epoch: int, status: str) -> str:
    """Compute progression A_t = SHA-256(A_{t-1} || epoch || status)."""
    digest = hashlib.sha256(f"{prior_accumulator_digest}:{epoch}:{status}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class BirthToken:
    schema_version: Literal["verifier-birth-token-1"]
    token_id: str
    genesis_key_digest: str
    birth_epoch: int
    commitment: str
    issued_at: str
    signature_base64url: str
    declared_parameters: dict[str, Any] | None = None

    def canonical_bytes(self) -> bytes:
        return canonical_token_bytes(asdict(self))


@dataclass(frozen=True)
class AgingToken:
    schema_version: Literal["verifier-aging-token-1"]
    token_id: str
    birth_token_id: str
    genesis_key_digest: str
    accumulated_epochs: int
    epoch_start: int
    epoch_end: int
    accumulator_digest: str
    revocation_status: Literal["ACTIVE", "REVOKED"]
    attested_by: str
    issued_at: str
    signature_base64url: str

    def canonical_bytes(self) -> bytes:
        return canonical_token_bytes(asdict(self))


@dataclass(frozen=True)
class LifetimeToken:
    schema_version: Literal["verifier-lifetime-token-1"]
    token_id: str
    actor_id: str
    delegate_key_id: str
    permitted_scopes: tuple[str, ...]
    not_before: str
    not_after: str
    soulbound: bool
    issuing_key_id: str
    issued_at: str
    signature_base64url: str
    max_invocations: int | None = None
    parent_grant_id: str | None = None

    def canonical_bytes(self) -> bytes:
        return canonical_token_bytes(asdict(self))
