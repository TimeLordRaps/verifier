"""Bounded consent admission for proposed level-7 closure coordinates.

Terminology: hash-based message authentication code (HMAC), Secure Hash Algorithm 256-bit
(SHA-256), JavaScript Object Notation (JSON), Coordinated Universal Time (UTC),
Unicode Transformation Format, 8-bit (UTF-8).
Authentication establishes a configured shared-key statement, not human consent,
legal authority, public-key attribution, or computational validity. Policy and
evaluation time must come from the trusted caller, never the submitted evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import math
import re
from typing import Any


class ConsentVerdict(str, Enum):
    PASS = "PASS"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ConsentContext:
    """Exact requested action. Timestamp is integer UTC Unix seconds."""
    object_name: str
    artifact_digest: str
    operation: str
    actor_id: str
    observer_id: str
    purpose: str
    timestamp: int


@dataclass(frozen=True)
class ConsentKey:
    """Externally configured actor/key binding; secret is never serialized."""
    key_id: str
    actor_id: str
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (type(self.key_id) is not str or not self.key_id or len(self.key_id) > 512
                or type(self.actor_id) is not str or not self.actor_id or len(self.actor_id) > 512
                or type(self.secret) is not bytes or len(self.secret) < 32):
            raise ValueError("consent key requires identity and at least 32 secret bytes")


@dataclass(frozen=True)
class ConsentPolicy:
    """Trusted configuration for one required consent holder and current key set.

The operator must establish that grantor_id can authorize the target artifact.
Root keys and revocation keys are distinct configured roles, not payload claims.
Freshness intervals are seconds; chain length is dimensionless.
"""
    policy_id: str
    grantor_id: str
    keys: tuple[ConsentKey, ...]
    root_key_ids: tuple[str, ...]
    revocation_key_ids: tuple[str, ...]
    artifact_bindings: tuple[tuple[str, str], ...] = ()
    max_revocation_age_seconds: int = 60
    minimum_revocation_as_of: int = 0
    max_chain_length: int = 8

    def __post_init__(self) -> None:
        if (type(self.keys) is not tuple or not all(type(key) is ConsentKey for key in self.keys)
                or type(self.root_key_ids) is not tuple or type(self.revocation_key_ids) is not tuple
                or type(self.artifact_bindings) is not tuple):
            raise ValueError("invalid trusted consent policy")
        identifiers = [key.key_id for key in self.keys]
        if (type(self.policy_id) is not str or not self.policy_id or len(self.policy_id) > 512
                or type(self.grantor_id) is not str or not self.grantor_id or len(self.grantor_id) > 512
                or not all(type(name) is str and 0 < len(name) <= 512
                           for name in self.root_key_ids + self.revocation_key_ids)
                or len(identifiers) != len(set(identifiers))
                or not self.root_key_ids or not self.revocation_key_ids
                or not set(self.root_key_ids + self.revocation_key_ids) <= set(identifiers)
                or type(self.max_revocation_age_seconds) is not int or self.max_revocation_age_seconds < 0
                or type(self.minimum_revocation_as_of) is not int or self.minimum_revocation_as_of < 0
                or type(self.max_chain_length) is not int or not 1 <= self.max_chain_length <= 16):
            raise ValueError("invalid trusted consent policy")
        if any(type(binding) is not tuple or len(binding) != 2 or type(binding[0]) is not str
               or not binding[0] or len(binding[0]) > 512 or type(binding[1]) is not str
               or not re.fullmatch(r"[0-9a-f]{64}", binding[1]) for binding in self.artifact_bindings):
            raise ValueError("invalid trusted artifact bindings")
        if any(key.actor_id != self.grantor_id for key in self.keys if key.key_id in self.root_key_ids):
            raise ValueError("root consent keys must bind the required grantor")


@dataclass(frozen=True)
class ConsentEvaluation:
    verdict: ConsentVerdict
    receipt: dict[str, Any]


class _Rejected(ValueError):
    pass


class _Unknown(ValueError):
    pass


_MAX_CAPTURE_NODES = 50000
_MAX_CAPTURE_DEPTH = 64
_MAX_CAPTURE_BYTES = 1_048_576


def _capture_plain(value: Any) -> Any:
    """Copy exact built-in JSON data under a pre-serialization size budget."""
    nodes = 0
    encoded_text = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, encoded_text
        nodes += 1
        if nodes > _MAX_CAPTURE_NODES or depth > _MAX_CAPTURE_DEPTH:
            raise _Rejected("consent evidence structural bound exhausted")
        if type(item) is dict:
            if len(item) > 10000:
                raise _Rejected("consent object bound exhausted")
            copied: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str or len(key) > 512:
                    raise _Rejected("consent object key is not plain bounded text")
                charge(key)
                copied[key] = visit(child, depth + 1)
            return copied
        if type(item) is list or type(item) is tuple:
            if len(item) > 10000:
                raise _Rejected("consent array bound exhausted")
            copied = [visit(child, depth + 1) for child in item]
            return tuple(copied) if type(item) is tuple else copied
        if type(item) is str:
            if len(item) > 512:
                raise _Rejected("consent text bound exhausted")
            charge(item)
            return item
        if type(item) is int:
            if item.bit_length() > 4096:
                raise _Rejected("consent integer bound exhausted")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise _Rejected("consent number is not finite")
            return item
        if item is None or type(item) is bool:
            return item
        raise _Rejected("consent data must use plain JSON values")

    def charge(value: str) -> None:
        nonlocal encoded_text
        try:
            encoded_text += len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise _Rejected("consent text is not UTF-8") from exc
        if encoded_text > _MAX_CAPTURE_BYTES:
            raise _Rejected("consent evidence exceeds one mebibyte")

    try:
        return visit(value, 0)
    except RuntimeError as exc:
        raise _Rejected("consent evidence changed during capture") from exc


def _capture_context(context: ConsentContext) -> ConsentContext:
    if type(context) is not ConsentContext:
        raise _Rejected("consent context must be a plain request")
    values = {name: getattr(context, name) for name in ConsentContext.__dataclass_fields__}
    for name, value in values.items():
        _time(value) if name == "timestamp" else _text(value)
    return ConsentContext(**values)


def _capture_policy(policy: ConsentPolicy | None) -> ConsentPolicy | None:
    if policy is None:
        return None
    if (type(policy) is not ConsentPolicy or type(policy.keys) is not tuple
            or type(policy.root_key_ids) is not tuple
            or type(policy.revocation_key_ids) is not tuple
            or type(policy.artifact_bindings) is not tuple):
        raise _Rejected("trusted consent policy must be plain")
    if (len(policy.keys) + len(policy.root_key_ids) + len(policy.revocation_key_ids)
            + len(policy.artifact_bindings) > _MAX_CAPTURE_NODES):
        raise _Rejected("trusted consent policy structural bound exhausted")
    if not all(type(key) is ConsentKey for key in policy.keys):
        raise _Rejected("trusted consent key must be plain")

    # Bound the public descriptor's source text before cloning configured keys.
    # Root byte strings remain trusted runtime inputs and are not descriptor text.
    text_bytes = 0

    def charge(value: Any) -> None:
        nonlocal text_bytes
        if type(value) is not str or len(value) > 512:
            raise _Rejected("trusted consent policy text is not plain and bounded")
        try:
            text_bytes += len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise _Rejected("trusted consent policy text is not UTF-8") from exc
        if text_bytes > _MAX_CAPTURE_BYTES:
            raise _Rejected("trusted consent policy exceeds descriptor text bound")

    charge(policy.policy_id)
    charge(policy.grantor_id)
    for key in policy.keys:
        charge(key.key_id)
        charge(key.actor_id)
        if type(key.secret) is not bytes or len(key.secret) < 32:
            raise _Rejected("trusted consent secret root is not plain")
    for value in (*policy.root_key_ids, *policy.revocation_key_ids):
        charge(value)
    for binding in policy.artifact_bindings:
        if type(binding) is not tuple or len(binding) != 2:
            raise _Rejected("trusted consent artifact binding is not plain")
        charge(binding[0])
        charge(binding[1])
    for value in (policy.max_revocation_age_seconds, policy.minimum_revocation_as_of,
                  policy.max_chain_length):
        if type(value) is not int or value.bit_length() > 4096:
            raise _Rejected("trusted consent policy integer bound exhausted")
    try:
        keys = tuple(ConsentKey(key.key_id, key.actor_id, key.secret) for key in policy.keys)
        captured = ConsentPolicy(
            policy_id=policy.policy_id, grantor_id=policy.grantor_id,
            keys=keys, root_key_ids=policy.root_key_ids,
            revocation_key_ids=policy.revocation_key_ids,
            artifact_bindings=policy.artifact_bindings,
            max_revocation_age_seconds=policy.max_revocation_age_seconds,
            minimum_revocation_as_of=policy.minimum_revocation_as_of,
            max_chain_length=policy.max_chain_length,
        )
        _bytes(_policy_descriptor(captured))
        return captured
    except (TypeError, ValueError, AttributeError) as exc:
        raise _Rejected("trusted consent policy is malformed") from exc


def _bytes(value: Any) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    if len(encoded) > 1_048_576:
        raise _Rejected("consent evidence exceeds one mebibyte")
    return encoded


def _digest(value: Any) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def _text(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise _Rejected("expected a nonempty bounded string")
    return value


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise _Rejected("time must be nonnegative integer Unix seconds")
    return value


def _fields(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _Rejected("unexpected or missing consent fields")
    return value


def _names(value: Any, *, empty: bool = False) -> set[str]:
    if type(value) is not list or len(value) > 128 or (not value and not empty):
        raise _Rejected("expected a bounded explicit name list")
    names = {_text(name) for name in value}
    if len(names) != len(value):
        raise _Rejected("duplicate consent scope names")
    return names


def authenticate_consent(payload: dict[str, Any], key: ConsentKey) -> dict[str, Any]:
    """Authenticate an exact grant or status body; this does not confer authority."""
    if type(key) is not ConsentKey:
        raise _Rejected("consent authentication key must be plain")
    key = ConsentKey(key.key_id, key.actor_id, key.secret)
    payload = _capture_plain(payload)
    body = {"key_id": key.key_id, "payload": payload}
    return {**body, "payload_digest": _digest(payload),
            "authenticator": hmac.new(key.secret, b"vstd-consent-1\0" + _bytes(body), hashlib.sha256).hexdigest()}


def _authenticate(envelope: Any, policy: ConsentPolicy) -> tuple[dict[str, Any], str]:
    _fields(envelope, {"key_id", "payload", "payload_digest", "authenticator"})
    key_id = _text(envelope["key_id"])
    if type(envelope["payload"]) is not dict:
        raise _Rejected("consent body must be an object")
    if _digest(envelope["payload"]) != envelope["payload_digest"]:
        raise _Rejected("consent payload digest mismatch")
    key = next((item for item in policy.keys if item.key_id == key_id), None)
    if key is None:
        raise _Unknown("consent signing key is not configured")
    expected = authenticate_consent(envelope["payload"], key)["authenticator"]
    if type(envelope["authenticator"]) is not str or not hmac.compare_digest(expected, envelope["authenticator"]):
        raise _Rejected("consent authenticator mismatch")
    if envelope["payload"].get("issuer_id") != key.actor_id:
        raise _Rejected("consent issuer differs from configured key actor")
    return envelope["payload"], key_id


def _policy_descriptor(policy: ConsentPolicy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {"policy_id": policy.policy_id, "grantor_id": policy.grantor_id,
            "keys": [{"key_id": key.key_id, "actor_id": key.actor_id,
                      "key_fingerprint": hashlib.sha256(key.secret).hexdigest()} for key in policy.keys],
            "root_key_ids": list(policy.root_key_ids), "revocation_key_ids": list(policy.revocation_key_ids),
            "artifact_bindings": [list(binding) for binding in policy.artifact_bindings],
            "max_revocation_age_seconds": policy.max_revocation_age_seconds,
            "minimum_revocation_as_of": policy.minimum_revocation_as_of,
            "max_chain_length": policy.max_chain_length}


_GRANT_FIELDS = {"schema_version", "grant_id", "issuer_id", "actor_id", "object_name", "artifact_digest",
                 "operations", "observer_ids", "purposes", "not_before", "not_after", "parent_digest",
                 "allow_delegation", "effect"}


def _evaluate(context: ConsentContext, grants: tuple[dict[str, Any], ...], policy: ConsentPolicy | None,
              revocation: dict[str, Any] | None, evaluation_time: int | None) -> None:
    now = None if evaluation_time is None else _time(evaluation_time)
    for name, value in asdict(context).items():
        _time(value) if name == "timestamp" else _text(value)
    if now is not None and context.timestamp != now:
        raise _Rejected("requested action time differs from trusted evaluation time")
    if not re.fullmatch(r"[0-9a-f]{64}", context.artifact_digest):
        raise _Rejected("artifact digest must be lowercase SHA-256 hexadecimal")
    if policy is None:
        raise _Unknown("trusted consent policy is unavailable")
    if policy.artifact_bindings and (context.object_name, context.artifact_digest) not in policy.artifact_bindings:
        raise _Rejected("artifact is outside configured grantor authority")
    if len(grants) > policy.max_chain_length:
        raise _Rejected("consent delegation chain exceeds policy bound")
    # Screen all submitted envelopes for independently decidable forgery, even
    # when the grant chain is absent. Defer unknown-key evidence to its use below:
    # an unknown status root cannot erase an authenticated grant's refutation.
    for envelope in (*grants, *((revocation,) if revocation is not None else ())):
        try:
            _authenticate(envelope, policy)
        except _Unknown:
            continue
    if not grants:
        raise _Unknown("consent grant chain is unavailable")
    parents: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, envelope in enumerate(grants):
        grant, key_id = _authenticate(envelope, policy)
        _fields(grant, _GRANT_FIELDS)
        if grant["schema_version"] != "verifier-consent-grant-1":
            raise _Rejected("unsupported consent grant version")
        for name in ("grant_id", "issuer_id", "actor_id", "object_name", "artifact_digest"):
            _text(grant[name])
        if grant["grant_id"] in identifiers:
            raise _Rejected("duplicate or cyclic consent grant identifier")
        identifiers.add(grant["grant_id"])
        if grant["effect"] not in ("ALLOW", "DENY") or type(grant["allow_delegation"]) is not bool:
            raise _Rejected("unsupported grant effect or delegation flag")
        scopes = {name: _names(grant[name]) for name in ("operations", "observer_ids", "purposes")}
        start, end = _time(grant["not_before"]), _time(grant["not_after"])
        if start >= end or (now is not None and not start <= now < end):
            raise _Rejected("consent grant is inactive or expired")
        if (grant["object_name"], grant["artifact_digest"]) != (context.object_name, context.artifact_digest):
            raise _Rejected("consent artifact binding mismatch")
        if index == 0:
            if key_id not in policy.root_key_ids or grant["issuer_id"] != policy.grantor_id or grant["parent_digest"] is not None:
                raise _Rejected("consent chain lacks configured root authority")
        else:
            parent = parents[-1]
            if not parent["allow_delegation"] or grant["issuer_id"] != parent["actor_id"]:
                raise _Rejected("consent delegation is not authorized by parent")
            if grant["parent_digest"] != grants[index - 1]["payload_digest"]:
                raise _Rejected("consent parent digest mismatch")
            if start < parent["not_before"] or end > parent["not_after"] or any(
                    not scopes[name] <= set(parent[name]) for name in scopes):
                raise _Rejected("consent delegation widens parent scope or validity")
        if grant["effect"] == "DENY":
            raise _Rejected("authenticated consent denial")
        parents.append(grant)
    leaf = parents[-1]
    if (leaf["actor_id"] != context.actor_id or context.operation not in leaf["operations"]
            or context.observer_id not in leaf["observer_ids"] or context.purpose not in leaf["purposes"]):
        raise _Rejected("action actor, recipient, purpose, or operation exceeds consent")
    if revocation is None:
        raise _Unknown("consent revocation evidence is unavailable")
    state, key_id = _authenticate(revocation, policy)
    _fields(state, {"schema_version", "issuer_id", "policy_id", "as_of", "next_update", "revoked_grant_ids"})
    if state["schema_version"] != "verifier-consent-revocations-1" or state["policy_id"] != policy.policy_id:
        raise _Rejected("consent revocation policy binding mismatch")
    if key_id not in policy.revocation_key_ids:
        raise _Rejected("consent revocation issuer is not authorized")
    as_of, next_update = _time(state["as_of"]), _time(state["next_update"])
    if as_of >= next_update:
        raise _Rejected("invalid consent revocation interval")
    revoked = _names(state["revoked_grant_ids"], empty=True)
    if now is not None and as_of > now:
        raise _Unknown("consent revocation snapshot is from the future")
    if identifiers & revoked:
        raise _Rejected("consent grant or ancestor was revoked")
    if now is None:
        raise _Unknown("trusted evaluation time is unavailable")
    if not policy.artifact_bindings:
        raise _Unknown("trusted grantor authority over the artifact is unavailable")
    if (now >= next_update or now - as_of > policy.max_revocation_age_seconds
            or as_of < policy.minimum_revocation_as_of):
        raise _Unknown("consent revocation freshness is not established")


def evaluate_consent(context: ConsentContext, grants: tuple[dict[str, Any], ...], *,
                     policy: ConsentPolicy | None, revocation: dict[str, Any] | None,
                     evaluation_time: int | None = None,
                     computational_verdict: str = "UNKNOWN") -> ConsentEvaluation:
    """Evaluate exact current admission; receipt replay requires external policy and time.

No authorization is enforced by this function and no underlying computation is rerun.
The preserved computational_verdict is caller input, never a certified conclusion.
"""
    if (type(computational_verdict) is not str
            or computational_verdict not in {"PASS", "FAIL", "UNKNOWN", "REJECTED", "CONFLICTED"}):
        raise ValueError("unsupported computational verdict")
    captured_context: ConsentContext | None = None
    captured_policy: ConsentPolicy | None = None
    captured_evidence: dict[str, Any] | None = None
    captured_evaluation_time: int | None = None
    policy_captured = False
    try:
        if evaluation_time is not None:
            captured_evaluation_time = _time(evaluation_time)
        captured_context = _capture_context(context)
        captured_policy = _capture_policy(policy)
        policy_captured = True
        if type(grants) is not tuple or len(grants) > 16:
            raise _Rejected("consent grant chain must be a bounded plain tuple")
        captured_evidence = _capture_plain({"grants": grants, "revocation": revocation})
        _evaluate(captured_context, captured_evidence["grants"], captured_policy,
                  captured_evidence["revocation"], captured_evaluation_time)
        verdict, reason = ConsentVerdict.PASS, "configured consent authority admits this exact action"
    except _Unknown as exc:
        verdict, reason = ConsentVerdict.UNKNOWN, str(exc)
    except (ValueError, TypeError, KeyError, RecursionError, AttributeError) as exc:
        verdict, reason = ConsentVerdict.REJECTED, str(exc)
    try:
        evidence_digest = _digest(captured_evidence) if captured_evidence is not None else None
    except (ValueError, TypeError, RecursionError):
        evidence_digest = None
    receipt = {"schema_version": "verifier-consent-receipt-1",
               "context": asdict(captured_context) if captured_context is not None else None,
               "evaluation_time": captured_evaluation_time,
               "policy_digest": _digest(_policy_descriptor(captured_policy)) if policy_captured else None,
               "evidence_digest": evidence_digest, "verdict": verdict.value, "reason": reason,
               "computational_verdict": computational_verdict, "enforcement": "NOT_ESTABLISHED"}
    receipt["receipt_digest"] = _digest(receipt)
    return ConsentEvaluation(verdict, receipt)


def recheck_consent(receipt: dict[str, Any], context: ConsentContext,
                    grants: tuple[dict[str, Any], ...], *, policy: ConsentPolicy | None,
                    revocation: dict[str, Any] | None, evaluation_time: int | None = None,
                    computational_verdict: str = "UNKNOWN") -> bool:
    """Rerun and compare all receipt fields; a matching UNKNOWN still is not consent."""
    try:
        retained = _capture_plain(receipt)
        if evaluation_time is not None:
            _time(evaluation_time)
        expected = evaluate_consent(context, grants, policy=policy, revocation=revocation,
                                    evaluation_time=evaluation_time,
                                    computational_verdict=computational_verdict)
        return _bytes(retained) == _bytes(expected.receipt)
    except (ValueError, TypeError, RecursionError):
        return False
