"""Configured-key admission of exact package owner decisions.

This mechanism authenticates one finite owner statement against separately
selected and digest-pinned policy bytes.  It does not create a private key,
choose the policy, infer legal authority, or turn candidate semantics into
normative closure.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Edwards-curve digital signature algorithm with a 255-bit field (Ed25519).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Mapping

from verifier.core.signature_keys import admit_ed25519_public_key
from verifier.runtime import core_obligation_union


POLICY_SCHEMA = "verifier-package-owner-decision-policy-1"
PAYLOAD_SCHEMA = "verifier-package-owner-decisions-1"
ENVELOPE_SCHEMA = "verifier-package-owner-decision-envelope-1"
ADMISSION_SCHEMA = "verifier-package-owner-decision-admission-1"
PREFIX = b"vstd-package-owner-decision-ed25519-1\0"
MAX_POLICY_BYTES = 64 * 1024
MAX_DECISION_BYTES = 2 * 1024 * 1024
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{128}\Z")
_OBJECT_KINDS = (
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER",
    "HARDWARE", "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT",
    "ENV", "DATA", "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER",
    "MODEL", "HARNESS", "AGENT", "SIM", "BOT", "TOKEN",
)
_EXPECTED_DECISION_IDS = frozenset(
    [f"CTC-{index}" for index in range(1, 7)]
    + [
        f"{kind}-Q{index}"
        for kind in _OBJECT_KINDS
        for index in range(1, 5)
    ]
)


class OwnerDecisionError(ValueError):
    """Selected owner-decision evidence contradicts its exact contract."""


class OwnerDecisionUnavailable(RuntimeError):
    """Selected owner-decision evidence cannot currently be evaluated."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    """Bind the exact admission implementation and public-key screen."""
    root = Path(__file__).parents[1]
    return core_obligation_union.value_digest({
        "owner_decision": _digest(Path(__file__).read_bytes()),
        "signature_key_admission": _digest(
            root.joinpath("core", "signature_keys.py").read_bytes()
        ),
        "canonical_value": _digest(
            root.joinpath("runtime", "core_obligation_union.py").read_bytes()
        ),
        "specification": _digest(
            root.joinpath(
                "standard", "PACKAGE_OWNER_DECISIONS.md"
            ).read_bytes()
        ),
        "signature_backend": "cryptography-50.0.0",
    })


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise OwnerDecisionError(code)


def _strict_json(raw: bytes, *, code: str) -> dict[str, Any]:
    _require(type(raw) is bytes, code)

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OwnerDecisionError(code)
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                OwnerDecisionError(code)
            ),
        )
    except OwnerDecisionError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError,
            RecursionError) as exc:
        raise OwnerDecisionError(code) from exc
    _require(type(value) is dict, code)
    return value


def _read(path: str | Path, *, maximum: int, code: str) -> bytes:
    descriptor: int | None = None
    try:
        selected = Path(path)
        if selected.is_symlink():
            raise OwnerDecisionError(code)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(selected, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OwnerDecisionUnavailable(code)
        size = metadata.st_size
        if not 0 < size <= maximum:
            raise OwnerDecisionError(code)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(maximum + 1)
    except OwnerDecisionError:
        raise
    except OwnerDecisionUnavailable:
        raise
    except (OSError, ValueError) as exc:
        raise OwnerDecisionUnavailable(code) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    _require(len(raw) == size and len(raw) <= maximum, code)
    return raw


def _canonical(value: Any, code: str) -> bytes:
    try:
        return core_obligation_union.canonical_bytes(value)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise OwnerDecisionError(code) from exc


def _hash(value: Any, code: str) -> str:
    _require(type(value) is str and _SHA256.fullmatch(value) is not None, code)
    return value


def _text(value: Any, code: str) -> str:
    _require(type(value) is str and 0 < len(value) <= 256, code)
    return value


def _time(value: Any, code: str) -> int:
    _require(type(value) is int and 0 <= value < 2**63, code)
    return value


def expected_owner_decisions(
        candidate_ledger: Mapping[str, Any]) -> list[dict[str, str]]:
    """Derive the exact 110-decision adoption denominator."""
    _require(type(candidate_ledger) is dict
             and candidate_ledger.get("status") == "PASS"
             and candidate_ledger.get("semantic_identity_status") == "PASS",
             "PACKAGE_OWNER_CANDIDATE_SELECTION_NOT_PASS")
    selected_digest = candidate_ledger.get("selection_digest")
    _hash(selected_digest, "PACKAGE_OWNER_CANDIDATE_SELECTION_DIGEST_INVALID")
    retained = dict(candidate_ledger)
    retained.pop("selection_digest", None)
    _require(
        _digest(_canonical(
            retained, "PACKAGE_OWNER_CANDIDATE_SELECTION_INVALID"
        )) == selected_digest,
        "PACKAGE_OWNER_CANDIDATE_SELECTION_DIGEST_DIFFERS",
    )
    rows = candidate_ledger.get("owner_decisions")
    _require(type(rows) is list
             and type(candidate_ledger.get("owner_decision_count")) is int
             and len(rows) == candidate_ledger.get("owner_decision_count") == 110,
             "PACKAGE_OWNER_DECISION_DENOMINATOR_DIFFERS")
    result = []
    for row in rows:
        _require(type(row) is dict and type(row.get("decision_id")) is str,
                 "PACKAGE_OWNER_DECISION_DENOMINATOR_INVALID")
        decision_id = row["decision_id"]
        result.append({
            "decision_id": decision_id,
            "decision_subject_digest": _digest(_canonical(
                row, "PACKAGE_OWNER_DECISION_DENOMINATOR_INVALID"
            )),
            "disposition": (
                "ADOPT_PROPOSED_MAPPING"
                if decision_id.startswith("CTC-")
                else "ADOPT_PROPOSED_DEFAULT"
            ),
        })
    result.sort(key=lambda row: row["decision_id"])
    _require(
        {row["decision_id"] for row in result} == _EXPECTED_DECISION_IDS,
        "PACKAGE_OWNER_DECISION_DENOMINATOR_DIFFERS",
    )
    return result


def decision_signing_bytes(payload_bytes: bytes, *, key_id: str) -> bytes:
    """Return the domain-separated message without reading a private key."""
    payload = _strict_json(
        payload_bytes, code="PACKAGE_OWNER_DECISION_PAYLOAD_INVALID"
    )
    body = {
        "schema_version": ENVELOPE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": _text(key_id, "PACKAGE_OWNER_DECISION_KEY_INVALID"),
        "payload": payload,
        "payload_digest": _digest(_canonical(
            payload, "PACKAGE_OWNER_DECISION_PAYLOAD_INVALID"
        )),
    }
    return PREFIX + _canonical(
        body, "PACKAGE_OWNER_DECISION_ENVELOPE_INVALID"
    )


def _base_admission(status: str, *, code: str | None = None) -> dict[str, Any]:
    body = {
        "schema_version": ADMISSION_SCHEMA,
        "status": status,
        "authority_scope": "CONFIGURED_KEY_OWNER_STATEMENT_ONLY",
        "owner_id": None,
        "policy_id": None,
        "policy_revision": None,
        "policy_digest": None,
        "decision_envelope_digest": None,
        "candidate_selection_digest": None,
        "source_coordinate_digest": None,
        "decision_set_digest": None,
        "decision_count": 0,
        "adopted_decision_ids": [],
        "evaluation_time": None,
        "mechanism_digest": mechanism_digest(),
        "error": code,
        "claim_boundary": (
            "PASS authenticates exact adoption of the selected 110 candidate "
            "decision subjects under separately supplied and digest-pinned "
            "configured-key policy bytes. It does not prove personhood, legal "
            "authority, candidate truth, normative closure, corrigibility, "
            "release, or deployment authority."
        ),
    }
    body["admission_digest"] = core_obligation_union.value_digest(body)
    return body


def not_selected_owner_decision_admission() -> dict[str, Any]:
    """Return the explicit absent-selection state."""
    return _base_admission("NOT_SELECTED")


def failed_owner_decision_admission(code: str) -> dict[str, Any]:
    """Return a bounded contradiction without retaining malformed inputs."""
    return _base_admission("FAIL", code=code)


def unavailable_owner_decision_admission(code: str) -> dict[str, Any]:
    """Return a bounded unavailable state without weakening it to absence."""
    return _base_admission("UNKNOWN", code=code)


def load_owner_decision_admission(
        candidate_ledger: Mapping[str, Any], *,
        source_coordinate_digest: str,
        policy_path: str | Path | None,
        expected_policy_digest: str | None,
        decision_path: str | Path | None,
        expected_decision_digest: str | None,
        evaluation_time: int | None = None,
        ) -> dict[str, Any]:
    """Authenticate the exact owner adoption statement selected by the host."""
    selected = (
        policy_path, expected_policy_digest,
        decision_path, expected_decision_digest,
    )
    if all(value is None for value in selected):
        return not_selected_owner_decision_admission()
    _require(all(value is not None for value in selected),
             "PACKAGE_OWNER_DECISION_SELECTION_INCOMPLETE")
    policy_digest = _hash(
        expected_policy_digest, "PACKAGE_OWNER_POLICY_DIGEST_INVALID"
    )
    envelope_digest = _hash(
        expected_decision_digest, "PACKAGE_OWNER_DECISION_DIGEST_INVALID"
    )
    source_digest = _hash(
        source_coordinate_digest, "PACKAGE_OWNER_SOURCE_DIGEST_INVALID"
    )
    policy_raw = None
    decision_raw = None
    unavailable: OwnerDecisionUnavailable | None = None
    try:
        policy_raw = _read(
            policy_path, maximum=MAX_POLICY_BYTES,
            code="PACKAGE_OWNER_POLICY_UNAVAILABLE",
        )
    except OwnerDecisionUnavailable as exc:
        unavailable = exc
    try:
        decision_raw = _read(
            decision_path, maximum=MAX_DECISION_BYTES,
            code="PACKAGE_OWNER_DECISION_UNAVAILABLE",
        )
    except OwnerDecisionUnavailable as exc:
        if unavailable is None:
            unavailable = exc
    if policy_raw is not None:
        _require(_digest(policy_raw) == policy_digest,
                 "PACKAGE_OWNER_POLICY_DIGEST_DIFFERS")
    if decision_raw is not None:
        _require(_digest(decision_raw) == envelope_digest,
                 "PACKAGE_OWNER_DECISION_DIGEST_DIFFERS")
    if unavailable is not None:
        raise unavailable
    if policy_raw is None or decision_raw is None:
        raise OwnerDecisionUnavailable(
            "PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE"
        )
    policy = _strict_json(policy_raw, code="PACKAGE_OWNER_POLICY_INVALID")
    _require(set(policy) == {
        "schema_version", "mechanism_digest", "policy_id", "revision",
        "owner_id", "key_id", "public_key", "effective_from",
        "effective_until", "max_decision_age_seconds",
    }, "PACKAGE_OWNER_POLICY_FIELDS_DIFFER")
    _require(policy["schema_version"] == POLICY_SCHEMA,
             "PACKAGE_OWNER_POLICY_SCHEMA_DIFFERS")
    _require(_hash(policy["mechanism_digest"],
                   "PACKAGE_OWNER_POLICY_MECHANISM_INVALID")
             == mechanism_digest(),
             "PACKAGE_OWNER_POLICY_MECHANISM_DIFFERS")
    policy_id = _text(policy["policy_id"], "PACKAGE_OWNER_POLICY_ID_INVALID")
    owner_id = _text(policy["owner_id"], "PACKAGE_OWNER_ID_INVALID")
    key_id = _text(policy["key_id"], "PACKAGE_OWNER_DECISION_KEY_INVALID")
    revision = _time(policy["revision"], "PACKAGE_OWNER_POLICY_REVISION_INVALID")
    _require(revision > 0, "PACKAGE_OWNER_POLICY_REVISION_INVALID")
    effective_from = _time(
        policy["effective_from"], "PACKAGE_OWNER_POLICY_TIME_INVALID"
    )
    effective_until = _time(
        policy["effective_until"], "PACKAGE_OWNER_POLICY_TIME_INVALID"
    )
    max_age = _time(
        policy["max_decision_age_seconds"],
        "PACKAGE_OWNER_POLICY_MAX_AGE_INVALID",
    )
    _require(0 < max_age and effective_from < effective_until,
             "PACKAGE_OWNER_POLICY_TIME_INVALID")
    _require(type(policy["public_key"]) is str
             and _HEX_32.fullmatch(policy["public_key"]) is not None,
             "PACKAGE_OWNER_PUBLIC_KEY_INVALID")
    try:
        public_key = admit_ed25519_public_key(
            bytes.fromhex(policy["public_key"])
        )
    except ValueError as exc:
        raise OwnerDecisionError(
            "PACKAGE_OWNER_PUBLIC_KEY_INVALID"
        ) from exc

    envelope = _strict_json(
        decision_raw, code="PACKAGE_OWNER_DECISION_ENVELOPE_INVALID"
    )
    _require(set(envelope) == {
        "schema_version", "algorithm", "key_id", "payload",
        "payload_digest", "signature",
    }, "PACKAGE_OWNER_DECISION_ENVELOPE_FIELDS_DIFFER")
    _require(envelope["schema_version"] == ENVELOPE_SCHEMA
             and envelope["algorithm"] == "Ed25519"
             and envelope["key_id"] == key_id,
             "PACKAGE_OWNER_DECISION_SIGNATURE_DOMAIN_DIFFERS")
    payload = envelope["payload"]
    _require(type(payload) is dict and set(payload) == {
        "schema_version", "policy_id", "policy_revision", "owner_id",
        "candidate_selection_digest", "source_coordinate_digest",
        "decision_set_digest", "decisions", "issued_at", "valid_until",
        "nonce",
    }, "PACKAGE_OWNER_DECISION_PAYLOAD_FIELDS_DIFFER")
    payload_bytes = _canonical(
        payload, "PACKAGE_OWNER_DECISION_ENVELOPE_INVALID"
    )
    _require(_hash(envelope["payload_digest"],
                   "PACKAGE_OWNER_DECISION_PAYLOAD_DIGEST_INVALID")
             == _digest(payload_bytes),
             "PACKAGE_OWNER_DECISION_PAYLOAD_DIGEST_DIFFERS")
    _require(type(envelope["signature"]) is str
             and _HEX_64.fullmatch(envelope["signature"]) is not None,
             "PACKAGE_OWNER_DECISION_SIGNATURE_INVALID")
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise OwnerDecisionUnavailable(
            "PACKAGE_OWNER_SIGNATURE_BACKEND_UNAVAILABLE"
        ) from exc
    if getattr(cryptography, "__version__", None) != "50.0.0":
        raise OwnerDecisionUnavailable(
            "PACKAGE_OWNER_SIGNATURE_BACKEND_VERSION_UNAVAILABLE"
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(envelope["signature"]),
            decision_signing_bytes(payload_bytes, key_id=key_id),
        )
    except UnsupportedAlgorithm as exc:
        raise OwnerDecisionUnavailable(
            "PACKAGE_OWNER_SIGNATURE_ALGORITHM_UNAVAILABLE"
        ) from exc
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise OwnerDecisionError(
            "PACKAGE_OWNER_DECISION_SIGNATURE_REFUSED"
        ) from exc

    now = int(time.time()) if evaluation_time is None else _time(
        evaluation_time, "PACKAGE_OWNER_EVALUATION_TIME_INVALID"
    )
    issued_at = _time(
        payload["issued_at"], "PACKAGE_OWNER_DECISION_TIME_INVALID"
    )
    valid_until = _time(
        payload["valid_until"], "PACKAGE_OWNER_DECISION_TIME_INVALID"
    )
    _require(effective_from <= issued_at <= now <= valid_until
             <= effective_until and now - issued_at <= max_age,
             "PACKAGE_OWNER_DECISION_NOT_CURRENT")
    payload_revision = _time(
        payload["policy_revision"],
        "PACKAGE_OWNER_DECISION_POLICY_BINDING_DIFFERS",
    )
    _require(payload["schema_version"] == PAYLOAD_SCHEMA
             and payload["policy_id"] == policy_id
             and payload_revision == revision
             and payload["owner_id"] == owner_id,
             "PACKAGE_OWNER_DECISION_POLICY_BINDING_DIFFERS")
    payload_candidate_digest = _hash(
        payload["candidate_selection_digest"],
        "PACKAGE_OWNER_CANDIDATE_SELECTION_DIGEST_INVALID",
    )
    payload_source_digest = _hash(
        payload["source_coordinate_digest"],
        "PACKAGE_OWNER_SOURCE_DIGEST_INVALID",
    )
    _hash(
        payload["decision_set_digest"],
        "PACKAGE_OWNER_DECISION_SET_DIGEST_INVALID",
    )
    _require(payload_source_digest == source_digest,
             "PACKAGE_OWNER_DECISION_SUBJECT_DIFFERS")
    if (type(candidate_ledger) is not dict
            or candidate_ledger.get("status") != "PASS"
            or candidate_ledger.get("semantic_identity_status") != "PASS"):
        raise OwnerDecisionUnavailable(
            "PACKAGE_OWNER_DECISION_SUBJECT_NOT_ESTABLISHED"
        )
    candidate_selection_digest = _hash(
        candidate_ledger.get("selection_digest"),
        "PACKAGE_OWNER_CANDIDATE_SELECTION_DIGEST_INVALID",
    )
    _require(payload_candidate_digest == candidate_selection_digest,
             "PACKAGE_OWNER_DECISION_SUBJECT_DIFFERS")
    expected_decisions = expected_owner_decisions(candidate_ledger)
    expected_set_digest = _digest(_canonical(
        expected_decisions, "PACKAGE_OWNER_DECISION_SET_INVALID"
    ))
    _require(payload["decision_set_digest"] == expected_set_digest
             and payload["decisions"] == expected_decisions,
             "PACKAGE_OWNER_DECISION_SET_DIFFERS")
    _text(payload["nonce"], "PACKAGE_OWNER_DECISION_NONCE_INVALID")

    body = _base_admission("PASS")
    body.update({
        "owner_id": owner_id,
        "policy_id": policy_id,
        "policy_revision": revision,
        "policy_digest": policy_digest,
        "decision_envelope_digest": envelope_digest,
        "candidate_selection_digest": candidate_selection_digest,
        "source_coordinate_digest": source_digest,
        "decision_set_digest": expected_set_digest,
        "decision_count": len(expected_decisions),
        "adopted_decision_ids": [
            row["decision_id"] for row in expected_decisions
        ],
        "evaluation_time": now,
        "error": None,
    })
    body.pop("admission_digest")
    body["admission_digest"] = core_obligation_union.value_digest(body)
    return body


__all__ = [
    "ADMISSION_SCHEMA", "ENVELOPE_SCHEMA", "MAX_DECISION_BYTES",
    "MAX_POLICY_BYTES", "PAYLOAD_SCHEMA", "POLICY_SCHEMA",
    "OwnerDecisionError", "OwnerDecisionUnavailable",
    "decision_signing_bytes", "expected_owner_decisions",
    "failed_owner_decision_admission", "load_owner_decision_admission",
    "mechanism_digest", "not_selected_owner_decision_admission",
    "unavailable_owner_decision_admission",
]
