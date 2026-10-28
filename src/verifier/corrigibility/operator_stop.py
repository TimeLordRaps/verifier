"""Configured-key authentication for one in-process stop request.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
The signature binds a selected operator key to an exact process identifier,
session, policy, action, request and time interval. Process identifiers and
verdicts are dimensionless; times are integer Coordinated Universal Time (UTC)
Unix seconds. Key configuration is trusted host input, not candidate evidence.
This module neither identifies a human nor stops a process or descendant.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.signature_keys import admit_ed25519_public_key


_SCHEMA = "verifier-operator-stop-1"
_PREFIX = b"vstd-operator-stop-ed25519-1\0"
_BODY_FIELDS = {"schema", "policy_digest", "session_id", "process_id", "action",
                "operator_id", "key_id", "request_id", "issued_at", "expires_at"}


def _text(value: Any) -> bool:
    if type(value) is not str or not 0 < len(value) <= 128:
        return False
    try:
        return len(value.encode("utf-8")) <= 512
    except UnicodeEncodeError:
        return False


@dataclass(frozen=True)
class OperatorStopKey:
    """One selected public key; possession and human authority are external."""

    operator_id: str
    key_id: str
    public_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _text(self.operator_id) or not _text(self.key_id):
            raise ValueError("operator and key identifiers must be bounded text")
        admit_ed25519_public_key(self.public_key)


@dataclass(frozen=True)
class OperatorStopPolicy:
    """Trusted selection of who may request STOP for a local session."""

    policy_id: str
    operators: tuple[OperatorStopKey, ...]
    max_request_age_seconds: int

    def __post_init__(self) -> None:
        if not _text(self.policy_id):
            raise ValueError("stop policy identifier must be bounded text")
        if (type(self.operators) is not tuple or not self.operators or len(self.operators) > 32
                or any(type(key) is not OperatorStopKey for key in self.operators)):
            raise ValueError("stop operators must be a nonempty bounded tuple")
        for values in ([key.operator_id for key in self.operators],
                       [key.key_id for key in self.operators],
                       [key.public_key for key in self.operators]):
            if len(set(values)) != len(values):
                raise ValueError("stop operator identities and keys must be distinct")
        if (type(self.max_request_age_seconds) is not int
                or not 1 <= self.max_request_age_seconds <= 3600):
            raise ValueError("stop request age bound must be 1..3600 seconds")

    @property
    def digest(self) -> str:
        public = {"schema": "verifier-operator-stop-policy-1", "policy_id": self.policy_id,
                  "max_request_age_seconds": self.max_request_age_seconds,
                  "operators": [{"operator_id": key.operator_id, "key_id": key.key_id,
                                 "public_key": key.public_key.hex()} for key in self.operators]}
        return "sha256:" + hashlib.sha256(canonical_bytes(public)).hexdigest()


def stop_signing_bytes(body: dict[str, Any]) -> bytes:
    """Domain-separated exact signing bytes for a bounded, plain request body."""
    if type(body) is not dict:
        raise ValueError("stop request body must be plain")
    body = body.copy()  # All admitted fields below are immutable scalar values.
    if any(type(name) is not str for name in body) or set(body) != _BODY_FIELDS:
        raise ValueError("stop request body must have exact fields")
    if not all(_text(body[name]) for name in (
            "schema", "policy_digest", "session_id", "action", "operator_id",
            "key_id", "request_id")):
        raise ValueError("stop request text is malformed or unbounded")
    if (type(body["process_id"]) is not int or type(body["issued_at"]) is not int
            or type(body["expires_at"]) is not int
            or any(not -(2**63) <= body[name] < 2**63
                   for name in ("process_id", "issued_at", "expires_at"))):
        raise ValueError("stop process and time coordinates must be exact integers")
    return _PREFIX + canonical_bytes(body)


def evaluate_stop_request(policy: OperatorStopPolicy, session_id: str, process_id: int,
                          request: Any, now: int) -> tuple[str, str | None]:
    """Return PASS, REJECTED or UNKNOWN and an accepted-request digest.

    This establishes only a signature by one configured key over the selected
    bytes. The clock, policy provenance, key custody and host routing remain
    outside this function's evidence boundary.
    """
    if type(request) is not dict:
        return "REJECTED", None
    # A plain built-in copy is the first read after type admission. Validate
    # and use this same envelope; replacing the caller's body later cannot
    # introduce a foreign .copy() hook or switch the verified signature.
    request = request.copy()
    if (any(type(name) is not str for name in request)
            or set(request) != {"body", "signature"}
            or type(request.get("body")) is not dict):
        return "REJECTED", None
    # Capture the exact plain body once: a caller mutating its original mapping
    # cannot make binding checks refer to bytes different from those verified.
    body, signature = request["body"].copy(), request["signature"]
    try:
        signed = stop_signing_bytes(body)
    except (ValueError, TypeError):
        return "REJECTED", None
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
        return "REJECTED", None
    if (body["schema"] != _SCHEMA or body["policy_digest"] != policy.digest
            or body["session_id"] != session_id or body["process_id"] != process_id
            or body["action"] != "STOP" or body["issued_at"] < 0
            or body["expires_at"] <= body["issued_at"]
            or not body["issued_at"] <= now < body["expires_at"]
            or now - body["issued_at"] > policy.max_request_age_seconds
            or body["expires_at"] - body["issued_at"] > policy.max_request_age_seconds):
        return "REJECTED", None
    key = next((key for key in policy.operators if key.key_id == body["key_id"]
                and key.operator_id == body["operator_id"]), None)
    if key is None:
        return "REJECTED", None
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "UNKNOWN", None
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(bytes.fromhex(signature), signed)
    except UnsupportedAlgorithm:
        return "UNKNOWN", None
    except (InvalidSignature, ValueError, TypeError):
        return "REJECTED", None
    retained = {"body": body, "signature": signature}
    return "PASS", "sha256:" + hashlib.sha256(canonical_bytes(retained)).hexdigest()
