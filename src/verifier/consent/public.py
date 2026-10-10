"""Public-key consent admission under independently selected authority and time.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); hash-based message authentication code (HMAC); Coordinated
Universal Time (UTC). Ed25519 is the signature algorithm. Time is integer UTC Unix
seconds; bounds are dimensionless unless measured in bytes. Existing HMAC wire
semantics remain separate. Public key possession is not human consent or authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core import signature_keys
from verifier.consent import engine as native
from verifier.consent.engine import ConsentContext, ConsentEvaluation, ConsentVerdict

POLICY_VERSION = "verifier-consent-public-policy-1"
ENVELOPE_VERSION = "verifier-consent-public-envelope-1"
RECEIPT_VERSION = "verifier-consent-public-receipt-1"
_PREFIX = b"vstd-consent-ed25519-1\0"
_Unknown = native._Unknown
_Rejected = native._Rejected
_POLICY_FIELDS = {"schema_version", "mechanism_digest", "policy_id", "grantor_id", "keys",
    "root_key_ids", "revocation_key_ids", "artifact_bindings", "max_revocation_age_seconds",
    "minimum_revocation_as_of", "max_chain_length"}
_ENVELOPE_FIELDS = {"schema_version", "algorithm", "key_id", "payload", "payload_digest", "signature"}
_RECEIPT_FIELDS = {"schema_version", "context", "evaluation_time", "policy_digest", "evidence_digest",
    "mechanism_digest", "verdict", "reason", "computational_verdict", "enforcement", "receipt_digest"}



@dataclass(frozen=True)
class _Key:
    key_id: str
    actor_id: str
    public_key: bytes


@dataclass(frozen=True)
class _Policy:
    policy_id: str
    grantor_id: str
    keys: tuple[_Key, ...]
    root_key_ids: tuple[str, ...]
    revocation_key_ids: tuple[str, ...]
    artifact_bindings: tuple[tuple[str, str], ...]
    max_revocation_age_seconds: int
    minimum_revocation_as_of: int
    max_chain_length: int


def mechanism_digest() -> str:
    """Bind this adapter, shared native rules and its installed specification."""
    paths = {"public.py": Path(__file__), "engine.py": Path(native.__file__),
        "signature_keys.py": Path(signature_keys.__file__),
        "CONSENT_PUBLIC_ADMISSION.md": Path(__file__).parents[1] / "standard" / "CONSENT_PUBLIC_ADMISSION.md"}
    return native._digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _hex(value: Any, length: int) -> bytes:
    if type(value) is not str or re.fullmatch("[0-9a-f]{" + str(length * 2) + "}", value) is None:
        raise _Rejected("canonical fixed-length hexadecimal bytes required")
    return bytes.fromhex(value)


def _names(value: Any, *, empty: bool = False) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 256:
        raise _Rejected("bounded plain policy name array required")
    names = tuple(native._text(item) for item in value)
    if (not names and not empty) or len(set(names)) != len(names):
        raise _Rejected("policy names must be distinct")
    return names


def _public_key(value: Any) -> bytes:
    """Reject noncanonical encodings and small-order keys before authentication.

    The encoded y coordinate is the lower 255 bits, a dimensionless field value.
    This public-data admission screen does not implement signature verification,
    prove secure key generation, or replace the optional cryptographic backend.
    """
    try:
        return signature_keys.admit_ed25519_public_key(_hex(value, 32))
    except ValueError as exc:
        raise _Rejected(str(exc)) from exc


def _capture_policy(value: Any) -> tuple[_Policy | None, dict[str, Any] | None]:
    if value is None:
        return None, None
    value = native._capture_plain(value)
    native._fields(value, _POLICY_FIELDS)
    if value["schema_version"] != POLICY_VERSION or value["mechanism_digest"] != mechanism_digest():
        raise _Rejected("public consent policy version or mechanism differs")
    policy_id, grantor_id = native._text(value["policy_id"]), native._text(value["grantor_id"])
    if type(value["keys"]) is not list or not 1 <= len(value["keys"]) <= 256:
        raise _Rejected("bounded public-key inventory required")
    keys = []
    for row in value["keys"]:
        native._fields(row, {"key_id", "actor_id", "public_key"})
        keys.append(_Key(native._text(row["key_id"]), native._text(row["actor_id"]), _public_key(row["public_key"])))
    ids = {key.key_id for key in keys}
    if len(ids) != len(keys) or len({key.public_key for key in keys}) != len(keys):
        raise _Rejected("public keys and identifiers must be distinct")
    roots, status = _names(value["root_key_ids"]), _names(value["revocation_key_ids"])
    if not set(roots + status) <= ids or set(roots) & set(status):
        raise _Rejected("grant and revocation roles require separate configured keys")
    if any(key.actor_id != grantor_id for key in keys if key.key_id in roots):
        raise _Rejected("root keys must bind the configured holder")
    bindings = value["artifact_bindings"]
    if type(bindings) is not list or len(bindings) > 256:
        raise _Rejected("bounded authority bindings required")
    captured = []
    for row in bindings:
        if type(row) is not list or len(row) != 2:
            raise _Rejected("authority binding requires object and exact digest")
        native._text(row[0]); _hex(row[1], 32); captured.append(tuple(row))
    if len(set(captured)) != len(captured):
        raise _Rejected("authority bindings must be distinct")
    age = native._time(value["max_revocation_age_seconds"])
    floor = native._time(value["minimum_revocation_as_of"])
    chain = value["max_chain_length"]
    if type(chain) is not int or not 1 <= chain <= 16:
        raise _Rejected("delegation limit must be an integer from one through sixteen")
    return _Policy(policy_id, grantor_id, tuple(keys), roots, status, tuple(captured), age, floor, chain), value


def public_consent_policy(*, policy_id: str, grantor_id: str, keys: list[dict[str, str]],
                          root_key_ids: list[str], revocation_key_ids: list[str],
                          artifact_bindings: list[list[str]], max_revocation_age_seconds: int = 60,
                          minimum_revocation_as_of: int = 0, max_chain_length: int = 8) -> dict[str, Any]:
    """Capture independently provisioned public authority terms; never secret keys."""
    _, captured = _capture_policy({"schema_version": POLICY_VERSION, "mechanism_digest": mechanism_digest(),
        "policy_id": policy_id, "grantor_id": grantor_id, "keys": keys, "root_key_ids": root_key_ids,
        "revocation_key_ids": revocation_key_ids, "artifact_bindings": artifact_bindings,
        "max_revocation_age_seconds": max_revocation_age_seconds,
        "minimum_revocation_as_of": minimum_revocation_as_of, "max_chain_length": max_chain_length})
    assert captured is not None
    return captured


def consent_signing_bytes(payload: dict[str, Any], key_id: str) -> bytes:
    """Return exact domain-separated signing bytes, without loading private keys."""
    key_id = native._text(key_id)
    captured = native._capture_plain(payload)
    if type(captured) is not dict:
        raise _Rejected("public consent payload requires a plain object")
    body = {"schema_version": ENVELOPE_VERSION, "algorithm": "Ed25519", "key_id": key_id,
        "payload": captured, "payload_digest": native._digest(captured)}
    return _PREFIX + native._bytes(body)


def _verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise _Unknown("public signature backend unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(signature_keys.admit_ed25519_public_key(public_key)).verify(signature, message)
    except UnsupportedAlgorithm as exc:
        raise _Unknown("public signature algorithm unavailable") from exc
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise _Rejected("public consent signature does not verify") from exc


def _authenticate(envelope: Any, policy: _Policy) -> tuple[dict[str, Any], str]:
    native._fields(envelope, _ENVELOPE_FIELDS)
    if envelope["schema_version"] != ENVELOPE_VERSION or envelope["algorithm"] != "Ed25519":
        raise _Rejected("public consent envelope version or algorithm differs")
    key_id = native._text(envelope["key_id"])
    if type(envelope["payload"]) is not dict:
        raise _Rejected("public consent payload requires an object")
    _hex(envelope["payload_digest"], 32)
    signature = _hex(envelope["signature"], 64)
    if native._digest(envelope["payload"]) != envelope["payload_digest"]:
        raise _Rejected("public consent payload digest differs")
    key = next((key for key in policy.keys if key.key_id == key_id), None)
    if key is None:
        raise _Unknown("public consent signing key is not configured")
    _verify_signature(key.public_key, signature, consent_signing_bytes(envelope["payload"], key_id))
    if envelope["payload"].get("issuer_id") != key.actor_id:
        raise _Rejected("public consent issuer differs from configured key actor")
    return envelope["payload"], key_id


def evaluate_public_consent(context: ConsentContext, grants: tuple[dict[str, Any], ...], *,
                            policy: dict[str, Any] | None, revocation: dict[str, Any] | None,
                            evaluation_time: int | None = None,
                            computational_verdict: str = "UNKNOWN") -> ConsentEvaluation:
    """Admit one exact action under configured public keys, authority terms and time.

    A signature proves only the configured-key statement. Holder authority, actual
    human consent, registry completeness, clock authenticity and enforcement remain
    external. No operation is performed. The retained computational verdict is input.
    """
    if type(computational_verdict) is not str or computational_verdict not in {"PASS", "FAIL", "UNKNOWN", "REJECTED", "CONFLICTED"}:
        raise ValueError("unsupported computational verdict")
    captured_context = descriptor = evidence = now = None
    policy_digest = evidence_digest = None
    try:
        now = None if evaluation_time is None else native._time(evaluation_time)
        captured_context = native._capture_context(context)
        captured_policy, descriptor = _capture_policy(policy)
        policy_digest = native._digest(descriptor) if descriptor is not None else None
        if type(grants) is not tuple or len(grants) > 16:
            raise _Rejected("public consent grant chain requires a bounded plain tuple")
        evidence = native._capture_plain({"grants": grants, "revocation": revocation})
        evidence_digest = native._digest(evidence)
        native._evaluate_authenticated(captured_context, evidence["grants"], captured_policy,
            evidence["revocation"], now, authenticate=_authenticate,
            grant_version="verifier-consent-public-grant-1",
            revocation_version="verifier-consent-public-revocations-1")
        verdict, reason = ConsentVerdict.PASS, "configured public-key consent authority admits this exact action"
    except _Unknown as exc:
        verdict, reason = ConsentVerdict.UNKNOWN, str(exc)
    except (ValueError, TypeError, KeyError, RecursionError, AttributeError) as exc:
        verdict, reason = ConsentVerdict.REJECTED, str(exc)
    receipt = {"schema_version": RECEIPT_VERSION,
        "context": asdict(captured_context) if captured_context is not None else None,
        "evaluation_time": now, "policy_digest": policy_digest,
        "evidence_digest": evidence_digest,
        "mechanism_digest": mechanism_digest(), "verdict": verdict.value, "reason": reason,
        "computational_verdict": computational_verdict, "enforcement": "NOT_ESTABLISHED"}
    receipt["receipt_digest"] = native._digest(receipt)
    return ConsentEvaluation(verdict, receipt)


def recheck_public_consent(receipt: dict[str, Any], context: ConsentContext,
                           grants: tuple[dict[str, Any], ...], *, policy: dict[str, Any] | None,
                           revocation: dict[str, Any] | None, evaluation_time: int | None = None,
                           computational_verdict: str = "UNKNOWN") -> dict[str, Any]:
    """Separate exact historical replay, unavailable verification and substitution.

    REPRODUCED may reproduce UNKNOWN or REJECTED; always inspect admission_status.
    A positive historical receipt with unavailable checking inputs is UNAVAILABLE,
    never a reproduced PASS or proof that the historical issuer forged evidence.
    """
    try:
        carried = native._capture_plain(receipt)
        native._fields(carried, _RECEIPT_FIELDS)
        digest = carried["receipt_digest"]
        if (carried["schema_version"] != RECEIPT_VERSION or carried["mechanism_digest"] != mechanism_digest()
                or digest != native._digest({k: v for k, v in carried.items() if k != "receipt_digest"})
                or carried["computational_verdict"] != computational_verdict
                or carried["enforcement"] != "NOT_ESTABLISHED"
                or carried["verdict"] not in {"PASS", "REJECTED", "UNKNOWN"}):
            raise _Rejected("carried public consent receipt differs")
        native._text(carried["reason"])
        for name in ("policy_digest", "evidence_digest"):
            if carried[name] is not None:
                _hex(carried[name], 32)
            elif carried["verdict"] == "PASS":
                raise _Rejected("positive consent receipt lacks a required binding")
        if carried["evaluation_time"] is not None:
            native._time(carried["evaluation_time"])
        elif carried["verdict"] == "PASS":
            raise _Rejected("positive consent receipt lacks trusted time")
        selected_context = native._capture_context(context)
        selected_time = None if evaluation_time is None else native._time(evaluation_time)
        if native._bytes(carried["context"]) != native._bytes(asdict(selected_context)):
            raise _Rejected("carried consent context differs from selected action")
        if selected_time is not None and carried["evaluation_time"] != selected_time:
            raise _Rejected("carried consent time differs from selected time")
        _, selected_policy = _capture_policy(policy)
        if selected_policy is not None and carried["policy_digest"] != native._digest(selected_policy):
            raise _Rejected("carried consent policy differs from selected authority")
        if type(grants) is not tuple or len(grants) > 16:
            raise _Rejected("public consent grant chain requires a bounded plain tuple")
        selected_evidence = native._capture_plain({"grants": grants, "revocation": revocation})
        if carried["evidence_digest"] != native._digest(selected_evidence):
            raise _Rejected("carried consent evidence differs from selected evidence")
        evaluation = evaluate_public_consent(selected_context, selected_evidence["grants"],
            policy=selected_policy, revocation=selected_evidence["revocation"],
            evaluation_time=selected_time, computational_verdict=computational_verdict)
        exact = native._bytes(carried) == native._bytes(evaluation.receipt)
        status = "REPRODUCED" if exact else "UNAVAILABLE" if evaluation.verdict == ConsentVerdict.UNKNOWN else "REJECTED"
        return {"replay_status": status, "admission_status": evaluation.verdict.value,
            "evaluation": evaluation.receipt, "enforcement": "NOT_ESTABLISHED"}
    except (ValueError, TypeError, KeyError, RecursionError, AttributeError):
        return {"replay_status": "REJECTED", "admission_status": "NOT_ESTABLISHED", "enforcement": "NOT_ESTABLISHED"}


__all__ = ["POLICY_VERSION", "ENVELOPE_VERSION", "RECEIPT_VERSION", "mechanism_digest",
    "public_consent_policy", "consent_signing_bytes", "evaluate_public_consent", "recheck_public_consent"]
