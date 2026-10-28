"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Public configured-key admission of one exact finite polish issuance subject.

Experimental bounded authority prerequisite; full positive issuance is separate. JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); Edwards-curve digital signature
algorithm with a 255-bit field (Ed25519). Timestamps use integer Unix seconds.
Configured key statements do not prove personhood, legal authority, denominator
completeness, native truth, consent, or atomic invocation consumption.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.signature_keys import admit_ed25519_public_key
from verifier.domains.contracts import certificate_dag as codec

POLICY = "verifier-polish-public-authority-policy-1"
CONTEXT = "verifier-polish-public-authority-context-1"
ENVELOPE = "verifier-polish-public-authority-envelope-1"
DECISION = "verifier-polish-public-authority-decision-1"
STATUS = "verifier-polish-public-authority-status-1"
ASSESSMENT = "verifier-polish-public-authority-assessment-1"
REPLAY = "verifier-polish-public-authority-replay-1"
OPERATION = "ISSUE_POLISHED_ARTIFACT"
FINITE_OPERATION = "ISSUE_FINITE_OBJECT_RECORD"
_OPERATIONS = (OPERATION, FINITE_OPERATION)
PREFIX = b"vstd-polish-public-authority-ed25519-1\0"
MAX_BYTES = 1024**2
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTEXT_FIELDS = {"schema_version", "mechanism_digest", "subject_digest", "policy_digest",
    "operation", "application_id", "profile_digest", "source_scope_digest", "collection_digest",
    "actor_id", "observer_id", "purpose", "jurisdiction", "timestamp", "invocation_id", "ledger_id", "policy_domain", "policy_epoch"}
_SCOPE_FIELDS = {"operation", "application_id", "profile_digest", "source_scope_digest",
                 "collection_digest", "jurisdiction", "ledger_id", "policy_domain", "policy_epoch"}


class AuthorityUnavailable(RuntimeError):
    """A configured public signature mechanism cannot currently evaluate evidence."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    root = Path(__file__).parents[1]
    paths = ("runtime/polish_public_authority.py", "core/signature_keys.py",
             "domains/contracts/certificate_dag.py", "core/certificate.py", "core/receipt.py",
             "standard/POLISH_PUBLIC_AUTHORITY.md")
    return _digest(canonical_bytes({"sources": {p: _digest((root / p).read_bytes()) for p in paths},
                                   "signature_backend": "cryptography-50.0.0"}))


def _load(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError("immutable bounded authority bytes required")
    return codec._parse(raw)


def _fields(value: Any, fields: set[str]) -> dict[str, Any]:
    return codec._record(value, fields)


def _text(value: Any) -> str:
    return codec._text(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("exact authority byte commitment required")
    return value


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("plain bounded integer authority time required")
    return value


def _names(value: Any, maximum: int = 256) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError("bounded plain authority identifier inventory required")
    result = [_text(v) for v in value]
    if len(set(result)) != len(result):
        raise ValueError("duplicate authority identifiers")
    return result


def _hex(value: Any, count: int) -> bytes:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{" + str(2 * count) + r"}", value) is None:
        raise ValueError("canonical authority hexadecimal bytes required")
    return bytes.fromhex(value)


def authority_signing_bytes(payload_bytes: bytes, *, key_id: str) -> bytes:
    """Format this new operation's signing message without reading a private key."""
    payload = _load(payload_bytes)
    body = {"schema_version": ENVELOPE, "algorithm": "Ed25519", "key_id": _text(key_id),
            "payload": payload, "payload_digest": _digest(payload_bytes)}
    return PREFIX + canonical_bytes(body)


def _envelope(envelope: Any) -> dict[str, Any]:
    _fields(envelope, {"schema_version", "algorithm", "key_id", "payload", "payload_digest", "signature"})
    if envelope["schema_version"] != ENVELOPE or envelope["algorithm"] != "Ed25519":
        raise ValueError("authority signature domain differs")
    _text(envelope["key_id"])
    payload = envelope["payload"]
    if type(payload) is not dict:
        raise ValueError("plain authority payload required")
    _hex(envelope["signature"], 64)
    if _hash(envelope["payload_digest"]) != _digest(canonical_bytes(payload)):
        raise ValueError("authority payload differs")
    return payload


def _authenticate(envelope: Any, keys: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], str]:
    payload = _envelope(envelope)
    key_id = _text(envelope["key_id"])
    if key_id not in keys:
        raise ValueError("unconfigured authority key")
    encoded = canonical_bytes(payload)
    signature = _hex(envelope["signature"], 64)
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise AuthorityUnavailable("authority signature backend unavailable") from error
    if getattr(cryptography, "__version__", None) != "50.0.0":
        raise AuthorityUnavailable("authority signature backend version unavailable")
    try:
        public = admit_ed25519_public_key(_hex(keys[key_id]["public_key"], 32))
        Ed25519PublicKey.from_public_bytes(public).verify(signature,
            authority_signing_bytes(encoded, key_id=key_id))
    except UnsupportedAlgorithm as error:
        raise AuthorityUnavailable("authority signature algorithm unavailable") from error
    except (InvalidSignature, TypeError, ValueError) as error:
        raise ValueError("authority signature refused") from error
    return payload, key_id


def _policy(raw: bytes, *, check_mechanism: bool = True) -> dict[str, Any]:
    policy = _load(raw)
    _fields(policy, {"schema_version", "mechanism_digest", "policy_id", "revision", "keys",
                    "voting_key_ids", "status_key_id", "quorum", "veto_actor_ids", "scopes",
                    "effective_from", "effective_until", "max_status_age_seconds"})
    if policy["schema_version"] != POLICY:
        raise ValueError("authority policy contract differs")
    _hash(policy["mechanism_digest"])
    _text(policy["policy_id"])
    if _time(policy["revision"]) < 1:
        raise ValueError("positive plain policy revision required")
    if type(policy["keys"]) is not list or not 2 <= len(policy["keys"]) <= 256:
        raise ValueError("bounded distinct voting and status keys required")
    keys = {}
    encodings = set()
    for row in policy["keys"]:
        _fields(row, {"key_id", "actor_id", "public_key"})
        key_id, actor = _text(row["key_id"]), _text(row["actor_id"])
        public = admit_ed25519_public_key(_hex(row["public_key"], 32))
        if key_id in keys or public in encodings:
            raise ValueError("duplicate authority public key or identifier")
        keys[key_id] = row
        encodings.add(public)
    voters = _names(policy["voting_key_ids"])
    status_key = _text(policy["status_key_id"])
    if not voters or not set(voters + [status_key]) <= keys.keys() or status_key in voters:
        raise ValueError("separate configured voting and status key roles required")
    actors = [keys[k]["actor_id"] for k in voters]
    if len(set(actors)) != len(actors):
        raise ValueError("voting actors must be distinct configured identifiers")
    if type(policy["quorum"]) is not int or not 1 <= policy["quorum"] <= len(voters):
        raise ValueError("achievable plain quorum required")
    if not set(_names(policy["veto_actor_ids"])) <= set(actors):
        raise ValueError("veto actor is outside configured electorate")
    scopes = policy["scopes"]
    if type(scopes) is not list or not 1 <= len(scopes) <= 256:
        raise ValueError("bounded exact authority scope matrix required")
    for row in scopes:
        _fields(row, _SCOPE_FIELDS)
        for key, value in row.items():
            if key == "policy_epoch":
                if _time(value) < 1:
                    raise ValueError("positive policy epoch required")
            else:
                (_hash if key.endswith("_digest") else _text)(value)
        if row["operation"] not in _OPERATIONS:
            raise ValueError("unsupported authority operation")
    if len({canonical_bytes(row) for row in scopes}) != len(scopes):
        raise ValueError("duplicate authority scope")
    for name in ("effective_from", "effective_until", "max_status_age_seconds"):
        _time(policy[name])
    if policy["effective_until"] <= policy["effective_from"]:
        raise ValueError("nonempty authority policy interval required")
    # Pure policy shape/key/role/scope contradictions precede source availability.
    # Deferral is internal only: no PASS or authenticated statement follows from it.
    if check_mechanism and policy["mechanism_digest"] != mechanism_digest():
        raise ValueError("authority policy mechanism differs")
    return policy


def assess_polish_authority(subject_bytes: bytes, *, context_bytes: bytes,
        evidence_bytes: bytes | None, trusted_policy_bytes: bytes | None,
        expected_trusted_policy_digest: str | None, evaluation_time: int | None) -> dict[str, Any]:
    """Authenticate one exact operation under separately supplied public policy roots.

    The host selects policy bytes and their expected digest from an authenticated
    operator channel. This pure function checks that selection; it cannot prove how
    its caller obtained authority. It never admits a producer's policy implicitly.
    """
    report = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "polished": False,
        "invocation_consumption": "NOT_PERFORMED", "authority_scope": "CONFIGURED_PUBLIC_KEY_STATEMENTS_ONLY",
        "claim_boundary": "Exact scoped configured-key statement only; completeness, native truth, "
                          "consent, human or legal authority and atomic consumption are separate.",
        "approving_actors": [], "checks": [], "replayable": False, "evaluation_time": None}
    failures, unavailable, approvals = [], [], set()
    try:
        if evaluation_time is not None:
            _time(evaluation_time)  # Never retain an unvalidated caller object.
            report["evaluation_time"] = evaluation_time
        for raw in (subject_bytes, context_bytes, evidence_bytes, trusted_policy_bytes):
            if raw is not None and (type(raw) is not bytes or len(raw) > MAX_BYTES):
                raise ValueError("immutable bounded authority bytes required")
        subject, context = _load(subject_bytes), _load(context_bytes)
        if trusted_policy_bytes is not None:
            _load(trusted_policy_bytes)  # Admit its immutable bound before any hash.
        _fields(context, _CONTEXT_FIELDS)
        if context["schema_version"] != CONTEXT:
            raise ValueError("authority context contract differs")
        for name, value in context.items():
            if name in ("timestamp", "policy_epoch"):
                if _time(value) < (1 if name == "policy_epoch" else 0):
                    raise ValueError("positive policy epoch required")
            elif name.endswith("_digest"):
                _hash(value)
            else:
                _text(value)
        if context["operation"] not in _OPERATIONS or context["subject_digest"] != _digest(subject_bytes):
            raise ValueError("authority operation or subject differs")
        for name in ("operation", "application_id", "profile_digest", "source_scope_digest", "collection_digest", "ledger_id", "policy_domain", "policy_epoch"):
            if subject.get(name) != context[name]:
                raise ValueError("authority subject scope differs")
        evidence = {"decisions": [], "status": None} if evidence_bytes is None else _load(evidence_bytes)
        _fields(evidence, {"decisions", "status"})
        if type(evidence["decisions"]) is not list or len(evidence["decisions"]) > 256:
            raise ValueError("bounded authority decisions required")
        # Structural contradictions and payload substitutions are decidable before
        # trusted-policy availability. An unauthenticated DENY itself is no verdict.
        local_ids, local_actors = set(), set()
        for envelope in evidence["decisions"]:
            row = _envelope(envelope)
            _fields(row, {"schema_version", "decision_id", "actor_id", "context_digest",
                          "policy_digest", "issued_at", "expires_at", "decision"})
            if row["schema_version"] != DECISION:
                raise ValueError("authority decision contract differs")
            for name in ("decision_id", "actor_id"):
                _text(row[name])
            for name in ("context_digest", "policy_digest"):
                _hash(row[name])
            if row["decision_id"] in local_ids or row["actor_id"] in local_actors:
                failures.append("DUPLICATE_LOCAL_DECISION_OR_ACTOR")
            local_ids.add(row["decision_id"])
            local_actors.add(row["actor_id"])
            if (row["context_digest"] != _digest(context_bytes)
                    or row["policy_digest"] != context["policy_digest"]):
                failures.append("DEMONSTRATED_ACTION_BINDING_MISMATCH")
            start, end = _time(row["issued_at"]), _time(row["expires_at"])
            if end <= start or row["decision"] not in ("APPROVE", "DENY", "VETO"):
                raise ValueError("authority decision shape or interval differs")
            if evaluation_time is not None and not start <= evaluation_time < end:
                failures.append("DEMONSTRATED_DECISION_TIME_MISMATCH")
        if evidence["status"] is not None:
            row = _envelope(evidence["status"])
            _fields(row, {"schema_version", "policy_digest", "ledger_id", "policy_domain", "policy_epoch", "observed_at", "expires_at",
                          "revoked_decisions", "revoked_actors", "consumed_invocations"})
            if row["schema_version"] != STATUS or _time(row["expires_at"]) <= _time(row["observed_at"]):
                raise ValueError("authority status contract or interval differs")
            _hash(row["policy_digest"])
            _text(row["ledger_id"])
            _text(row["policy_domain"])
            if _time(row["policy_epoch"]) < 1:
                raise ValueError("positive signed status epoch required")
            if any(row[name] != context[name] for name in
                   ("policy_digest", "ledger_id", "policy_domain", "policy_epoch")):
                failures.append("DEMONSTRATED_STATUS_SCOPE_MISMATCH")
            for name in ("revoked_decisions", "revoked_actors", "consumed_invocations"):
                _names(row[name])
        report.update(subject_digest=_digest(subject_bytes),
            context_digest=_digest(context_bytes), evaluation_time=evaluation_time,
            input_digests={"subject": _digest(subject_bytes), "context": _digest(context_bytes),
                "evidence": None if evidence_bytes is None else _digest(evidence_bytes),
                "policy": None if trusted_policy_bytes is None else _digest(trusted_policy_bytes)}, replayable=False)
        if evaluation_time is None:
            unavailable.append("TRUSTED_CLOCK_UNAVAILABLE")
        else:
            if context["timestamp"] != evaluation_time:
                failures.append("ACTION_CLOCK_MISMATCH")
        if expected_trusted_policy_digest is not None:
            if _hash(expected_trusted_policy_digest) != context["policy_digest"]:
                failures.append("INDEPENDENT_CONTEXT_POLICY_PIN_MISMATCH")
        # A present malformed declared policy is a local contract refusal even
        # when an external trust pin is absent. This authenticates no authority.
        declared_policy = None if trusted_policy_bytes is None else _policy(trusted_policy_bytes, check_mechanism=False)
        if trusted_policy_bytes is None or expected_trusted_policy_digest is None:
            unavailable.append("TRUSTED_POLICY_UNAVAILABLE")
        else:
            policy = declared_policy
            if (_hash(expected_trusted_policy_digest) != _digest(trusted_policy_bytes)
                    or context["policy_digest"] != expected_trusted_policy_digest):
                raise ValueError("independent authority policy pin differs")
            if {k: context[k] for k in _SCOPE_FIELDS} not in policy["scopes"]:
                failures.append("OUTSIDE_CONFIGURED_SCOPE")
            if evaluation_time is not None and not policy["effective_from"] <= evaluation_time < policy["effective_until"]:
                failures.append("POLICY_NOT_EFFECTIVE")
            keys = {row["key_id"]: row for row in policy["keys"]}
            # Refuse policy/input contradictions before any optional signature call.
            # These checks authenticate no vote, revocation, consumed ID or actor.
            # Exact envelope and payload fields were already captured above.
            for envelope in evidence["decisions"]:
                row, key_id = envelope["payload"], envelope["key_id"]
                if (key_id not in keys or key_id not in policy["voting_key_ids"]
                        or row["actor_id"] != keys[key_id]["actor_id"]
                        or row["actor_id"] == context["actor_id"]):
                    failures.append("DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH")
                if row["decision"] == "VETO" and row["actor_id"] not in policy["veto_actor_ids"]:
                    failures.append("DEMONSTRATED_UNCONFIGURED_VETO_ROLE")
            if evidence["status"] is not None and evidence["status"]["key_id"] != policy["status_key_id"]:
                failures.append("DEMONSTRATED_POLICY_STATUS_ROLE_MISMATCH")
            if policy["mechanism_digest"] != context["mechanism_digest"]:
                raise ValueError("declared authority context/policy mechanism differs")
            # Every independently available local binding/time/policy refusal has
            # been recorded. Fresh source reconstruction remains mandatory before
            # actual signatures or any positive/replayable assessment.
            source = mechanism_digest()
            if context["mechanism_digest"] != source or policy["mechanism_digest"] != source:
                raise ValueError("authority context or policy mechanism differs")
            report.update(mechanism_digest=source, replayable=True)
            seen_ids, seen_actors = set(), set()
            for envelope in evidence["decisions"]:
                try:
                    row, key_id = _authenticate(envelope, keys)
                    _fields(row, {"schema_version", "decision_id", "actor_id", "context_digest",
                                  "policy_digest", "issued_at", "expires_at", "decision"})
                    actor, decision_id = _text(row["actor_id"]), _text(row["decision_id"])
                    if (row["schema_version"] != DECISION or key_id not in policy["voting_key_ids"]
                            or actor != keys[key_id]["actor_id"] or actor == context["actor_id"]):
                        raise ValueError("decision actor or role differs")
                    if decision_id in seen_ids or actor in seen_actors:
                        raise ValueError("duplicate authority decision or actor")
                    seen_ids.add(decision_id)
                    seen_actors.add(actor)
                    if (row["context_digest"] != _digest(context_bytes)
                            or row["policy_digest"] != expected_trusted_policy_digest):
                        raise ValueError("signed action binding differs")
                    start, end = _time(row["issued_at"]), _time(row["expires_at"])
                    if end <= start or evaluation_time is not None and not start <= evaluation_time < end:
                        raise ValueError("decision is not effective")
                    if row["decision"] == "APPROVE":
                        approvals.add(actor)
                    elif row["decision"] == "DENY" or row["decision"] == "VETO" and actor in policy["veto_actor_ids"]:
                        failures.append("EXPLICIT_DENIAL_OR_VETO")
                    else:
                        raise ValueError("unsupported decision kind")
                except AuthorityUnavailable:
                    unavailable.append("PUBLIC_SIGNATURE_BACKEND_UNAVAILABLE")
                except (codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
                    unavailable.append("AUTHORITY_RESOURCE_BOUND_EXHAUSTED")
                    report["replayable"] = False
                except (ValueError, TypeError, KeyError, UnicodeError):
                    failures.append("AUTHORITY_DECISION_REFUSED")
            if len(approvals) < policy["quorum"]:
                unavailable.append("QUORUM_NOT_ESTABLISHED")
            if evidence["status"] is None:
                unavailable.append("SIGNED_STATUS_UNAVAILABLE")
            else:
                try:
                    row, key_id = _authenticate(evidence["status"], keys)
                    _fields(row, {"schema_version", "policy_digest", "ledger_id", "policy_domain", "policy_epoch", "observed_at", "expires_at",
                                  "revoked_decisions", "revoked_actors", "consumed_invocations"})
                    if (row["schema_version"] != STATUS or key_id != policy["status_key_id"]
                            or row["policy_digest"] != expected_trusted_policy_digest
                             or any(row[name] != context[name] for name in
                                    ("ledger_id", "policy_domain", "policy_epoch"))):
                        raise ValueError("signed status root or scope differs")
                    observed, expires = _time(row["observed_at"]), _time(row["expires_at"])
                    if expires <= observed:
                        raise ValueError("invalid signed status interval")
                    if evaluation_time is not None and (not observed <= evaluation_time < expires
                            or evaluation_time - observed > policy["max_status_age_seconds"]):
                        unavailable.append("SIGNED_STATUS_NOT_CURRENT")
                    revoked_decisions = _names(row["revoked_decisions"])
                    revoked_actors = _names(row["revoked_actors"])
                    consumed = _names(row["consumed_invocations"])
                    if seen_ids.intersection(revoked_decisions) or seen_actors.intersection(revoked_actors):
                        failures.append("REVOKED_DECISION_OR_ACTOR")
                    if context["invocation_id"] in consumed:
                        failures.append("KNOWN_INVOCATION_REPLAY")
                except AuthorityUnavailable:
                    unavailable.append("PUBLIC_SIGNATURE_BACKEND_UNAVAILABLE")
                except (codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
                    unavailable.append("AUTHORITY_RESOURCE_BOUND_EXHAUSTED")
                    report["replayable"] = False
                except (ValueError, TypeError, KeyError, UnicodeError):
                    failures.append("AUTHORITY_STATUS_REFUSED")
    except (OSError, ImportError):
        unavailable.append("AUTHORITY_SOURCE_UNAVAILABLE")
        report["replayable"] = False
    except (codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
        unavailable.append("AUTHORITY_RESOURCE_BOUND_EXHAUSTED")
        report["replayable"] = False
    except (ValueError, TypeError, KeyError, UnicodeError):
        failures.append("INVALID_OR_SUBSTITUTED_AUTHORITY_INPUT")
    report.update(status="FAIL" if failures else "UNKNOWN" if unavailable else "PASS",
        approving_actors=sorted(approvals), checks=sorted(set(failures + unavailable)))
    if "AUTHORITY_RESOURCE_BOUND_EXHAUSTED" in unavailable:
        report["reason"] = "AUTHORITY_RESOURCE_BOUND_EXHAUSTED"
    if report["replayable"]:
        try:
            encoded = canonical_bytes(report)
            if len(encoded) > MAX_BYTES:
                return {"schema_version": ASSESSMENT, "status": "FAIL" if failures else "UNKNOWN", "polished": False,
                        "reason": "AUTHORITY_OUTPUT_CAPACITY_EXHAUSTED", "replayable": False,
                        "checks": sorted(set(failures))}
            report["assessment_digest"] = _digest(encoded)
        except (codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
            report.update(status="FAIL" if failures else "UNKNOWN", replayable=False,
                reason="AUTHORITY_RESOURCE_BOUND_EXHAUSTED",
                checks=sorted(set(failures + unavailable + ["AUTHORITY_RESOURCE_BOUND_EXHAUSTED"])))
    return report


def recheck_polish_authority(assessment_bytes: bytes, **external_selection: Any) -> dict[str, Any]:
    """Validate retained bindings before current source/backend availability.

    UNKNOWN/UNAVAILABLE never carries an earlier PASS. A newly observed FAIL
    remains FAIL even if a later unavailable source makes it nonreplayable.
    """
    result = {"schema_version": REPLAY, "status": "FAIL", "replay_status": "REJECTED", "polished": False}
    observed_failure = False
    try:
        _fields(external_selection, {"subject_bytes", "context_bytes", "evidence_bytes",
            "trusted_policy_bytes", "expected_trusted_policy_digest", "evaluation_time"})
        inputs = {"subject": external_selection["subject_bytes"],
            "context": external_selection["context_bytes"], "evidence": external_selection["evidence_bytes"],
            "policy": external_selection["trusted_policy_bytes"]}
        # Inspect every selected transport before decoding/hashing any sibling.
        if type(assessment_bytes) is not bytes or len(assessment_bytes) > MAX_BYTES:
            raise ValueError("bounded immutable retained authority assessment required")
        for raw in inputs.values():
            if raw is not None and (type(raw) is not bytes or len(raw) > MAX_BYTES):
                raise ValueError("bounded immutable external authority inputs required")
        stored = _load(assessment_bytes)
        required = {"schema_version", "status", "polished", "invocation_consumption",
            "authority_scope", "claim_boundary", "approving_actors", "checks", "replayable",
            "evaluation_time", "mechanism_digest", "subject_digest", "context_digest",
            "input_digests", "assessment_digest"}
        if set(stored) not in (required, required | {"reason"}):
            raise ValueError("complete retained replayable authority assessment required")
        if (stored["schema_version"] != ASSESSMENT or stored["status"] not in ("PASS", "FAIL", "UNKNOWN")
                or stored["polished"] is not False or stored["replayable"] is not True
                or stored["invocation_consumption"] != "NOT_PERFORMED"
                or stored["authority_scope"] != "CONFIGURED_PUBLIC_KEY_STATEMENTS_ONLY"
                or stored["claim_boundary"] != "Exact scoped configured-key statement only; completeness, native truth, "
                    "consent, human or legal authority and atomic consumption are separate."
                or _hash(stored["assessment_digest"]) != _digest(canonical_bytes(
                    {k: v for k, v in stored.items() if k != "assessment_digest"}))):
            raise ValueError("retained authority outcome or commitment differs")
        for name in ("mechanism_digest", "subject_digest", "context_digest"):
            _hash(stored[name])
        _names(stored["approving_actors"])
        _names(stored["checks"], maximum=1024)
        if "reason" in stored:
            _text(stored["reason"])
        if stored["evaluation_time"] is not None:
            _time(stored["evaluation_time"])
        pins = _fields(stored["input_digests"], set(inputs))
        for name, pin in pins.items():
            if pin is not None:
                _hash(pin)
            if inputs[name] is not None and _digest(inputs[name]) != pin:
                raise ValueError("known retained authority input selection differs")
        if pins["subject"] != stored["subject_digest"] or pins["context"] != stored["context_digest"]:
            raise ValueError("retained direct and input commitments differ")
        now = external_selection["evaluation_time"]
        if now is not None and _time(now) != stored["evaluation_time"]:
            raise ValueError("known historical authority clock differs")
        expected = external_selection["expected_trusted_policy_digest"]
        if expected is not None:
            _hash(expected)
            if pins["policy"] is not None and expected != pins["policy"]:
                raise ValueError("known independent authority policy pin differs")
        if any(raw is None and pins[name] is not None for name, raw in inputs.items()):
            return {**result, "status": "UNKNOWN", "replay_status": "UNAVAILABLE",
                    "reason": "EXACT_RETAINED_AUTHORITY_INPUT_UNAVAILABLE"}
        actual = assess_polish_authority(**external_selection)
        if actual.get("status") == "FAIL":
            observed_failure = True
            result["reason"] = "CURRENT_AUTHORITY_REFUSED"
        if actual.get("replayable") is True and canonical_bytes(stored) == canonical_bytes(actual):
            result.update(status=actual["status"], replay_status="REPRODUCED", assessment_digest=actual["assessment_digest"])
        elif actual.get("status") == "FAIL":
            result["reason"] = "CURRENT_AUTHORITY_REFUSED"
        elif actual.get("status") == "UNKNOWN" or actual.get("replayable") is not True:
            result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="CURRENT_AUTHORITY_UNAVAILABLE")
    except (OSError, ImportError, codec._Exhausted, RecursionError, OverflowError, asyncio.CancelledError):
        if not observed_failure:
            result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="AUTHORITY_REPLAY_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    return result
