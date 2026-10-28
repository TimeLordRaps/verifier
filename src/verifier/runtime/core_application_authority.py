"""Private additive binding for a host-selected core application denominator.

The module binds a submitted nine-core requirements record to immutable host
selections.  Its versioned configured-key replay can establish only an exact
selected scope-admission or semantic-completeness statement.  Missing, stale,
cancelled or carried evidence remains UNKNOWN; forgery and substitution fail.
Human or legal authority, acceptance, polish and release remain separate.
"""
from __future__ import annotations

from asyncio import CancelledError
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


AUTHORITY_PROFILE_SCHEMA = "verifier-core-application-authority-profile-private-1"
APPLICABILITY_CLAIM_SCHEMA = "verifier-core-application-applicability-claim-private-1"
ASSESSMENT_SCHEMA = "verifier-core-application-authority-assessment-private-1"
UNION_AUTHORITY_SCHEMA = "verifier-core-obligation-union-authority-candidate-1"
CORE_REQUIREMENTS_SCHEMA = "verifier-core-application-required-instances-1"
CORE_PROFILE = "verifier-core-nine-tier-application-release-1"
CORRIGIBILITY_EXTENSION = "verifier-corrigibility-extension-selection-1"
COMPILER_SCHEMA = "verifier-current-application-obligations-1"
SCOPE_SUBJECT_SCHEMA = "verifier-application-scope-admission-subject-1"
SCOPE_OPERATION = "ADMIT_APPLICATION_REQUIREMENT_SCOPE"
SEMANTIC_COMPLETENESS_OPERATION = "ESTABLISH_APPLICATION_SEMANTIC_COMPLETENESS"
SEMANTIC_COMPLETENESS_SUBJECT_SCHEMA = (
    "verifier-core-application-semantic-completeness-subject-private-1")
AUTHORITY_POLICY_SCHEMA = "verifier-core-application-qualified-authority-policy-private-1"
AUTHORITY_RECEIPT_SCHEMA = "verifier-core-application-qualified-authority-receipt-private-1"
AUTHORITY_APPROVAL_SCHEMA = "verifier-core-application-qualified-authority-approval-private-1"
AUTHORITY_STATUS_SCHEMA = "verifier-core-application-qualified-authority-status-private-1"
AUTHORITY_SIGNATURE_SCHEMA = "verifier-core-application-qualified-authority-signature-private-1"
AUTHORITY_REPLAY_SCHEMA = "verifier-core-application-qualified-authority-replay-private-1"
FULL_SCOPE = "full-current-application-1"

MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_INSTANCES = 16384
MAX_MEMBERS = 16384
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{128}\Z")
_SIGNATURE_PREFIX = b"vstd-core-application-qualified-authority-ed25519-1\0"

OBJECT_KINDS = (
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS", "AGENT",
    "SIM", "BOT", "TOKEN",
)
TIER_NAMES = {
    1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE",
    5: "INDEPENDENCE", 6: "PRIVACY", 7: "CONSENT", 8: "GOVERNANCE", 9: "SECURITY",
}
CORE_INSTANCE_FIELDS = {
    "instance_id", "object_id", "operation_id", "context_digest", "instruction_digest",
    "generation", "shard_id", "node_id", "tier", "semantic_version", "objective",
    "proposition_digest", "request_digest", "checker_policy_digest",
}

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
COMPILER_INPUT_NAMES = {"source_scope", "collection", "selection", "compiler_policy"}
COMPILER_MEMBER_SET_NAMES = {
    "source_census", "namespace_census", "normative_family_census",
    "semantic_facet_census", "interaction_census", "applicability_ledger",
    "required_objectives", "native_dependency_profiles", "native_projection",
    "consumer_requirements", "unresolved_cells",
}


class _Refuted(ValueError):
    pass


class _Unavailable(ValueError):
    pass


@dataclass(frozen=True)
class QualifiedAuthorityReplaySelection:
    """Exact host-selected inputs for one installed authority receipt replay."""

    policy_bytes: bytes
    expected_policy_digest: str
    receipt_bytes: bytes
    expected_receipt_digest: str
    expected_mechanism_digest: str
    expected_operation: str
    expected_operation_revision_digest: str
    expected_instruction_revision_digest: str
    expected_context_revision_digest: str
    expected_subject_digest: str
    evaluation_time: int
    minimum_status_sequence: int


@dataclass(frozen=True)
class ApplicationAuthorityHostSelection:
    """Authenticated host-channel inputs; never decoded from candidate bytes."""

    profile_bytes: bytes
    expected_profile_digest: str
    union_authority_bytes: bytes
    expected_union_authority_digest: str
    union_contributions_bytes: bytes
    expected_union_contributions_digest: str
    expected_consumer_source_coordinate: dict[str, Any]
    expected_consumer_source_coordinate_digest: str
    expected_application_mechanism_digest: str
    expected_compiler_mechanism_digest: str
    expected_union_validator_digest: str
    scope_admission_receipt_bytes: bytes | None
    expected_scope_admission_receipt_digest: str | None
    scope_admission_replay: QualifiedAuthorityReplaySelection | None = None
    semantic_completeness_replay: QualifiedAuthorityReplaySelection | None = None


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def value_digest(value: Any) -> str:
    return bytes_digest(canonical_bytes(value))


def text_digest(text: str) -> str:
    return bytes_digest(text.encode("utf-8"))


def mechanism_digest() -> str:
    return value_digest({
        "schema_version": "verifier-private-core-application-authority-mechanism-2",
        "authority_module": bytes_digest(Path(__file__).read_bytes()),
        "authority_spec": bytes_digest(
            (PACKAGE_ROOT / "standard" / "CORE_APPLICATION_AUTHORITY.md").read_bytes()),
        "union_validator": installed_union_validator_digest(),
    })


def qualified_authority_mechanism_digest(operation: str) -> str:
    """Bind one supported receipt operation to this installed source and specification."""
    if operation not in (SCOPE_OPERATION, SEMANTIC_COMPLETENESS_OPERATION):
        raise ValueError("unsupported qualified authority operation")
    return value_digest({
        "schema_version": "verifier-core-application-qualified-authority-mechanism-private-1",
        "operation": operation,
        "authority_module": bytes_digest(Path(__file__).read_bytes()),
        "authority_spec": bytes_digest(
            (PACKAGE_ROOT / "standard" / "CORE_APPLICATION_AUTHORITY.md").read_bytes()),
        "signature_backend": "cryptography-50.0.0",
    })


def authority_signing_bytes(payload_bytes: bytes, *, key_id: str) -> bytes:
    """Return the domain-separated bytes signed by a selected authority key."""
    _require(type(payload_bytes) is bytes and len(payload_bytes) <= MAX_RECORD_BYTES,
             "AUTHORITY_SIGNATURE_PAYLOAD_FIELDS")
    _text(key_id, "AUTHORITY_SIGNATURE_KEY_FIELDS")
    return _SIGNATURE_PREFIX + canonical_bytes({
        "schema_version": AUTHORITY_SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload_digest": bytes_digest(payload_bytes),
    })


def _load_union_validator():
    try:
        from verifier.runtime import core_obligation_union
    except (ImportError, AttributeError):
        raise _Unavailable("UNION_VALIDATOR_UNAVAILABLE")
    if not callable(getattr(core_obligation_union, "validate_union", None)):
        raise _Unavailable("UNION_VALIDATOR_UNAVAILABLE")
    return core_obligation_union


def installed_union_validator_digest() -> str:
    module = _load_union_validator()
    installed_digest = getattr(module, "mechanism_digest", None)
    if callable(installed_digest):
        return installed_digest()
    return bytes_digest(Path(module.__file__).read_bytes())


def installed_compiler_mechanism_digest() -> str:
    try:
        from verifier.domains.contracts import application_requirements
    except (ImportError, AttributeError):
        raise _Unavailable("COMPILER_MECHANISM_UNAVAILABLE")
    installed_digest = getattr(application_requirements, "mechanism_digest", None)
    if not callable(installed_digest):
        raise _Unavailable("COMPILER_MECHANISM_UNAVAILABLE")
    return installed_digest()


def installed_application_mechanism_digest() -> str:
    """Exact digest of the installed core application consumer."""
    try:
        from verifier.runtime import core_application_release
    except (ImportError, AttributeError):
        raise _Unavailable("APPLICATION_MECHANISM_UNAVAILABLE")
    installed_digest = getattr(core_application_release, "mechanism_digest", None)
    if not callable(installed_digest):
        raise _Unavailable("APPLICATION_MECHANISM_UNAVAILABLE")
    return installed_digest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Refuted(code)


def _keys(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields, code)
    return value


def _text(value: Any, code: str) -> str:
    _require(type(value) is str and 0 < len(value) <= 4096 and bool(value.strip()), code)
    return value


def _hash(value: Any, code: str, *, optional: bool = False) -> str | None:
    _require((value is None and optional) or
             (type(value) is str and _HASH.fullmatch(value) is not None), code)
    return value


def _decode(raw: bytes, code: str) -> dict[str, Any]:
    _require(type(raw) is bytes, code)
    if len(raw) > MAX_RECORD_BYTES:
        raise _Unavailable("AUTHORITY_INPUT_CAPACITY_EXHAUSTED")
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise _Refuted(code)
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(_Refuted(code)))
    except _Refuted:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise _Refuted(code) from exc
    _require(type(value) is dict and canonical_bytes(value) == raw, code)
    return value


def _decode_list(raw: bytes, code: str) -> list[Any]:
    _require(type(raw) is bytes, code)
    if len(raw) > MAX_RECORD_BYTES:
        raise _Unavailable("AUTHORITY_INPUT_CAPACITY_EXHAUSTED")
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise _Refuted(code)
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(_Refuted(code)))
    except _Refuted:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise _Refuted(code) from exc
    _require(type(value) is list and canonical_bytes(value) == raw, code)
    return value


def _integer(value: Any, code: str, *, minimum: int = 0) -> int:
    _require(type(value) is int and minimum <= value < 2**63, code)
    return value


def _hex(value: Any, pattern: re.Pattern[str], code: str) -> bytes:
    _require(type(value) is str and pattern.fullmatch(value) is not None, code)
    return bytes.fromhex(value)


def _authority_envelope(value: Any, code: str) -> tuple[dict[str, Any], str, bytes]:
    _keys(value, {"schema_version", "algorithm", "key_id", "payload",
                  "payload_digest", "signature"}, code)
    _require(value["schema_version"] == AUTHORITY_SIGNATURE_SCHEMA
             and value["algorithm"] == "Ed25519", code)
    key_id = _text(value["key_id"], code)
    _require(type(value["payload"]) is dict, code)
    payload_bytes = canonical_bytes(value["payload"])
    _require(_hash(value["payload_digest"], code) == bytes_digest(payload_bytes), code)
    signature = _hex(value["signature"], _HEX_64, code)
    return value["payload"], key_id, signature


def _authenticate_authority_envelope(value: Any, keys: dict[str, dict[str, Any]],
                                     code: str) -> tuple[dict[str, Any], str]:
    payload, key_id, signature = _authority_envelope(value, code)
    _require(key_id in keys, code)
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from verifier.core.signature_keys import admit_ed25519_public_key
    except ImportError as exc:
        raise _Unavailable("AUTHORITY_SIGNATURE_BACKEND_UNAVAILABLE") from exc
    if getattr(cryptography, "__version__", None) != "50.0.0":
        raise _Unavailable("AUTHORITY_SIGNATURE_BACKEND_VERSION_UNAVAILABLE")
    try:
        public = admit_ed25519_public_key(
            _hex(keys[key_id]["public_key"], _HEX_32, code))
        encoded = canonical_bytes(payload)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, authority_signing_bytes(encoded, key_id=key_id))
    except UnsupportedAlgorithm as exc:
        raise _Unavailable("AUTHORITY_SIGNATURE_ALGORITHM_UNAVAILABLE") from exc
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise _Refuted(code) from exc
    return payload, key_id


def _authority_policy(raw: bytes, selection: QualifiedAuthorityReplaySelection
                      ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    policy = _decode(raw, "AUTHORITY_POLICY_FIELDS")
    _keys(policy, {"schema_version", "mechanism_digest", "policy_id", "revision",
                   "operation", "operation_revision_digest",
                   "instruction_revision_digest", "context_revision_digest", "keys",
                   "approval_key_ids", "status_key_id", "quorum", "effective_from",
                   "effective_until", "max_status_age_seconds"},
          "AUTHORITY_POLICY_FIELDS")
    _require(policy["schema_version"] == AUTHORITY_POLICY_SCHEMA,
             "AUTHORITY_POLICY_VERSION_DIFFERS")
    _text(policy["policy_id"], "AUTHORITY_POLICY_FIELDS")
    _integer(policy["revision"], "AUTHORITY_POLICY_FIELDS", minimum=1)
    for name in ("mechanism_digest", "operation_revision_digest",
                 "instruction_revision_digest", "context_revision_digest"):
        _hash(policy[name], "AUTHORITY_POLICY_FIELDS")
    _require(policy["mechanism_digest"] == selection.expected_mechanism_digest,
             "AUTHORITY_POLICY_MECHANISM_DIFFERS")
    _require(policy["operation"] == selection.expected_operation,
             "AUTHORITY_OPERATION_DIFFERS")
    _require(policy["operation_revision_digest"]
             == selection.expected_operation_revision_digest
             and policy["instruction_revision_digest"]
             == selection.expected_instruction_revision_digest
             and policy["context_revision_digest"]
             == selection.expected_context_revision_digest,
             "AUTHORITY_POLICY_REVISION_DIFFERS")
    _require(type(policy["keys"]) is list and 2 <= len(policy["keys"]) <= 256,
             "AUTHORITY_POLICY_KEYS_DIFFER")
    keys: dict[str, dict[str, Any]] = {}
    actors, public_keys = set(), set()
    for row in policy["keys"]:
        _keys(row, {"key_id", "actor_id", "public_key"}, "AUTHORITY_POLICY_KEYS_DIFFER")
        key_id = _text(row["key_id"], "AUTHORITY_POLICY_KEYS_DIFFER")
        actor_id = _text(row["actor_id"], "AUTHORITY_POLICY_KEYS_DIFFER")
        public = _hex(row["public_key"], _HEX_32, "AUTHORITY_POLICY_KEYS_DIFFER")
        _require(key_id not in keys and actor_id not in actors and public not in public_keys,
                 "AUTHORITY_POLICY_KEYS_DIFFER")
        keys[key_id] = row
        actors.add(actor_id)
        public_keys.add(public)
    approval_ids = policy["approval_key_ids"]
    _require(type(approval_ids) is list and bool(approval_ids)
             and len(approval_ids) == len(set(approval_ids))
             and all(type(item) is str and item in keys for item in approval_ids),
             "AUTHORITY_POLICY_APPROVAL_KEYS_DIFFER")
    status_key_id = _text(policy["status_key_id"], "AUTHORITY_POLICY_STATUS_KEY_DIFFERS")
    _require(status_key_id in keys and status_key_id not in approval_ids,
             "AUTHORITY_POLICY_STATUS_KEY_DIFFERS")
    _require(type(policy["quorum"]) is int
             and 1 <= policy["quorum"] <= len(approval_ids),
             "AUTHORITY_POLICY_QUORUM_DIFFERS")
    effective_from = _integer(policy["effective_from"], "AUTHORITY_POLICY_TIME_DIFFERS")
    effective_until = _integer(policy["effective_until"], "AUTHORITY_POLICY_TIME_DIFFERS")
    _require(effective_from < effective_until, "AUTHORITY_POLICY_TIME_DIFFERS")
    _integer(policy["max_status_age_seconds"], "AUTHORITY_POLICY_TIME_DIFFERS", minimum=1)
    return policy, keys


def replay_qualified_authority_receipt(selection: QualifiedAuthorityReplaySelection,
        *, required_operation: str, required_subject_digest: str) -> dict[str, Any]:
    """Recheck one exact configured-key receipt under installed source and host pins."""
    report = {
        "schema_version": AUTHORITY_REPLAY_SCHEMA,
        "status": "UNKNOWN",
        "replay_status": "NOT_ESTABLISHED",
        "operation": required_operation,
        "subject_digest": required_subject_digest,
        "receipt_digest": None,
        "policy_digest": None,
        "approving_actors": [],
        "blockers": [],
        "claim_boundary": (
            "Exact current configured-key statement only; signatures do not establish "
            "personhood, legal authority, denominator truth, human acceptance or release."),
    }
    try:
        _require(type(selection) is QualifiedAuthorityReplaySelection,
                 "AUTHORITY_REPLAY_SELECTION_REQUIRED")
        for raw in (selection.policy_bytes, selection.receipt_bytes):
            _require(type(raw) is bytes, "AUTHORITY_REPLAY_SELECTION_REQUIRED")
            if len(raw) > MAX_RECORD_BYTES:
                raise _Unavailable("AUTHORITY_INPUT_CAPACITY_EXHAUSTED")
        for value in (selection.expected_policy_digest, selection.expected_receipt_digest,
                      selection.expected_mechanism_digest,
                      selection.expected_operation_revision_digest,
                      selection.expected_instruction_revision_digest,
                      selection.expected_context_revision_digest,
                      selection.expected_subject_digest, required_subject_digest):
            _hash(value, "AUTHORITY_REPLAY_SELECTION_FIELDS")
        _text(selection.expected_operation, "AUTHORITY_REPLAY_SELECTION_FIELDS")
        evaluation_time = _integer(selection.evaluation_time,
                                   "AUTHORITY_EVALUATION_TIME_DIFFERS")
        minimum_sequence = _integer(selection.minimum_status_sequence,
                                    "AUTHORITY_STATUS_SEQUENCE_DIFFERS")
        _require(selection.expected_operation == required_operation,
                 "AUTHORITY_OPERATION_DIFFERS")
        _require(selection.expected_subject_digest == required_subject_digest,
                 "AUTHORITY_SUBJECT_DIFFERS")
        installed = qualified_authority_mechanism_digest(required_operation)
        _require(selection.expected_mechanism_digest == installed,
                 "AUTHORITY_MECHANISM_DIFFERS")
        _require(bytes_digest(selection.policy_bytes) == selection.expected_policy_digest,
                 "AUTHORITY_POLICY_DIGEST_DIFFERS")
        _require(bytes_digest(selection.receipt_bytes) == selection.expected_receipt_digest,
                 "AUTHORITY_RECEIPT_DIGEST_DIFFERS")
        report["policy_digest"] = selection.expected_policy_digest
        report["receipt_digest"] = selection.expected_receipt_digest

        policy, keys = _authority_policy(selection.policy_bytes, selection)
        _require(policy["effective_from"] <= evaluation_time < policy["effective_until"],
                 "AUTHORITY_POLICY_NOT_CURRENT")
        receipt = _decode(selection.receipt_bytes, "AUTHORITY_RECEIPT_FIELDS")
        receipt_body_fields = {
            "schema_version", "mechanism_digest", "receipt_id", "requester_id",
            "policy_digest", "operation", "operation_revision_digest",
            "instruction_revision_digest", "context_revision_digest", "subject_digest",
            "decision", "execution_status", "evidence_state", "issued_at", "expires_at",
        }
        _keys(receipt, receipt_body_fields | {"approvals", "status"},
              "AUTHORITY_RECEIPT_FIELDS")
        _require(receipt["schema_version"] == AUTHORITY_RECEIPT_SCHEMA,
                 "AUTHORITY_RECEIPT_VERSION_DIFFERS")
        for name in ("receipt_id", "requester_id"):
            _text(receipt[name], "AUTHORITY_RECEIPT_FIELDS")
        for name in ("mechanism_digest", "policy_digest", "operation_revision_digest",
                     "instruction_revision_digest", "context_revision_digest",
                     "subject_digest"):
            _hash(receipt[name], "AUTHORITY_RECEIPT_FIELDS")
        _require(receipt["mechanism_digest"] == installed
                 and receipt["policy_digest"] == selection.expected_policy_digest,
                 "AUTHORITY_RECEIPT_MECHANISM_OR_POLICY_DIFFERS")
        _require(receipt["operation"] == required_operation,
                 "AUTHORITY_OPERATION_DIFFERS")
        _require(receipt["operation_revision_digest"]
                 == selection.expected_operation_revision_digest
                 and receipt["instruction_revision_digest"]
                 == selection.expected_instruction_revision_digest
                 and receipt["context_revision_digest"]
                 == selection.expected_context_revision_digest,
                 "AUTHORITY_RECEIPT_REVISION_DIFFERS")
        _require(receipt["subject_digest"] == required_subject_digest,
                 "AUTHORITY_SUBJECT_DIFFERS")
        issued_at = _integer(receipt["issued_at"], "AUTHORITY_RECEIPT_TIME_DIFFERS")
        expires_at = _integer(receipt["expires_at"], "AUTHORITY_RECEIPT_TIME_DIFFERS")
        _require(issued_at <= evaluation_time < expires_at,
                 "AUTHORITY_RECEIPT_NOT_CURRENT")
        _require(receipt["decision"] in ("ADMIT", "DENY")
                 and receipt["execution_status"] in ("COMPLETED", "CANCELLED", "UNKNOWN")
                 and receipt["evidence_state"] in ("CURRENT", "CARRIED"),
                 "AUTHORITY_RECEIPT_FIELDS")
        receipt_body = {name: receipt[name] for name in receipt_body_fields}
        body_digest = value_digest(receipt_body)

        approvals = receipt["approvals"]
        _require(type(approvals) is list and len(approvals) <= 256,
                 "AUTHORITY_APPROVAL_FIELDS")
        approval_ids, approval_actors, approving_actors = set(), set(), set()
        for envelope in approvals:
            # Refute bounded submitted claims before any optional crypto work.
            # These checks grant no authority; every envelope is authenticated below.
            payload, key_id, _ = _authority_envelope(
                envelope, "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
            _require(key_id in keys, "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
            _keys(payload, {"schema_version", "approval_id", "actor_id",
                            "receipt_body_digest", "decision", "issued_at", "expires_at"},
                  "AUTHORITY_APPROVAL_FIELDS")
            _require(payload["schema_version"] == AUTHORITY_APPROVAL_SCHEMA
                     and key_id in policy["approval_key_ids"],
                     "AUTHORITY_APPROVAL_ROLE_DIFFERS")
            approval_id = _text(payload["approval_id"], "AUTHORITY_APPROVAL_FIELDS")
            actor_id = _text(payload["actor_id"], "AUTHORITY_APPROVAL_FIELDS")
            _require(actor_id == keys[key_id]["actor_id"]
                     and actor_id != receipt["requester_id"],
                     "AUTHORITY_APPROVAL_ROLE_DIFFERS")
            _require(approval_id not in approval_ids and actor_id not in approval_actors,
                     "AUTHORITY_APPROVAL_DUPLICATE")
            approval_ids.add(approval_id)
            approval_actors.add(actor_id)
            _require(_hash(payload["receipt_body_digest"], "AUTHORITY_APPROVAL_FIELDS")
                     == body_digest and payload["decision"] == "APPROVE",
                     "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
            approval_start = _integer(payload["issued_at"], "AUTHORITY_APPROVAL_TIME_DIFFERS")
            approval_end = _integer(payload["expires_at"], "AUTHORITY_APPROVAL_TIME_DIFFERS")
            _require(approval_start < approval_end, "AUTHORITY_APPROVAL_TIME_DIFFERS")
            if approval_start <= evaluation_time < approval_end:
                approving_actors.add(actor_id)

        status, status_key_id, _ = _authority_envelope(
            receipt["status"], "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
        _require(status_key_id in keys, "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
        _keys(status, {"schema_version", "policy_digest", "receipt_id", "sequence",
                       "observed_at", "expires_at", "revoked_approval_ids",
                       "revoked_actor_ids"}, "AUTHORITY_STATUS_FIELDS")
        _require(status["schema_version"] == AUTHORITY_STATUS_SCHEMA
                 and status_key_id == policy["status_key_id"],
                 "AUTHORITY_STATUS_ROLE_DIFFERS")
        _require(status["policy_digest"] == selection.expected_policy_digest
                 and status["receipt_id"] == receipt["receipt_id"],
                 "AUTHORITY_STATUS_BINDING_DIFFERS")
        sequence = _integer(status["sequence"], "AUTHORITY_STATUS_SEQUENCE_DIFFERS")
        _require(sequence >= minimum_sequence, "AUTHORITY_STATUS_SEQUENCE_DIFFERS")
        observed_at = _integer(status["observed_at"], "AUTHORITY_STATUS_TIME_DIFFERS")
        status_expires = _integer(status["expires_at"], "AUTHORITY_STATUS_TIME_DIFFERS")
        _require(observed_at < status_expires, "AUTHORITY_STATUS_TIME_DIFFERS")
        _require(type(status["revoked_approval_ids"]) is list
                 and type(status["revoked_actor_ids"]) is list,
                 "AUTHORITY_STATUS_FIELDS")
        revoked_ids = {_text(item, "AUTHORITY_STATUS_FIELDS")
                       for item in status["revoked_approval_ids"]}
        revoked_actors = {_text(item, "AUTHORITY_STATUS_FIELDS")
                          for item in status["revoked_actor_ids"]}
        _require(len(revoked_ids) == len(status["revoked_approval_ids"])
                 and len(revoked_actors) == len(status["revoked_actor_ids"]),
                 "AUTHORITY_STATUS_FIELDS")
        # Authentication remains mandatory for all authority, quorum, revocation
        # and decision facts. Pure preflight cannot establish their truth.
        for envelope in approvals:
            _authenticate_authority_envelope(
                envelope, keys, "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
        _authenticate_authority_envelope(
            receipt["status"], keys, "AUTHORITY_RECEIPT_SIGNATURE_REFUSED")
        if approval_ids & revoked_ids or approval_actors & revoked_actors:
            raise _Refuted("AUTHORITY_APPROVAL_REVOKED")
        report["approving_actors"] = sorted(approving_actors)

        if not (observed_at <= evaluation_time < status_expires
                and evaluation_time - observed_at <= policy["max_status_age_seconds"]):
            report["blockers"].append("AUTHORITY_STATUS_NOT_CURRENT")
        if len(approving_actors) < policy["quorum"]:
            report["blockers"].append("AUTHORITY_QUORUM_NOT_ESTABLISHED")
        if receipt["execution_status"] != "COMPLETED":
            report["blockers"].append("AUTHORITY_EXECUTION_NOT_COMPLETED")
        if receipt["evidence_state"] != "CURRENT":
            report["blockers"].append("AUTHORITY_EVIDENCE_NOT_CURRENT")
        if receipt["decision"] == "DENY":
            raise _Refuted("AUTHORITY_EXPLICIT_DENIAL")
        if not report["blockers"]:
            report["status"] = "PASS"
            report["replay_status"] = "REPRODUCED"
    except _Unavailable as exc:
        report["blockers"].append(str(exc))
    except (CancelledError, MemoryError, RecursionError, OverflowError):
        report["blockers"].append("AUTHORITY_REPLAY_RESOURCE_OR_CANCELLED_UNAVAILABLE")
    except (_Refuted, KeyError, TypeError, ValueError, UnicodeError) as exc:
        report["status"] = "FAIL"
        report["replay_status"] = "REJECTED"
        report["blockers"].append(str(exc) if isinstance(exc, _Refuted)
                                  else "AUTHORITY_RECEIPT_CONTRACT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]))
    report["replay_digest"] = value_digest(report)
    return report


def semantic_completeness_subject(*, profile_digest: str, requirements_digest: str,
        union_authority_digest: str, union_contributions_digest: str,
        compiler_manifest_digest: str, scope_admission_subject_digest: str,
        scope_admission_receipt_digest: str, consumer_source_coordinate_digest: str,
        application_mechanism_digest: str, compiler_mechanism_digest: str,
        union_validator_digest: str) -> dict[str, Any]:
    """Construct the exact composition attested by a selected semantic receipt."""
    values = {
        "profile_digest": profile_digest,
        "requirements_digest": requirements_digest,
        "union_authority_digest": union_authority_digest,
        "union_contributions_digest": union_contributions_digest,
        "compiler_manifest_digest": compiler_manifest_digest,
        "scope_admission_subject_digest": scope_admission_subject_digest,
        "scope_admission_receipt_digest": scope_admission_receipt_digest,
        "consumer_source_coordinate_digest": consumer_source_coordinate_digest,
        "application_mechanism_digest": application_mechanism_digest,
        "compiler_mechanism_digest": compiler_mechanism_digest,
        "union_validator_digest": union_validator_digest,
    }
    for value in values.values():
        _hash(value, "SEMANTIC_COMPLETENESS_SUBJECT_FIELDS")
    return {
        "schema_version": SEMANTIC_COMPLETENESS_SUBJECT_SCHEMA,
        "operation": SEMANTIC_COMPLETENESS_OPERATION,
        **values,
    }


def _coordinate(value: Any, code: str) -> dict[str, Any]:
    _require(type(value) is dict and bool(value) and len(canonical_bytes(value)) <= 65536, code)
    return value


def _source(value: Any) -> tuple[str, str]:
    _keys(value, {"uri", "sha256"}, "UNION_EXPECTED_MEMBER_DIFFERS")
    return _text(value["uri"], "UNION_EXPECTED_MEMBER_DIFFERS"), _hash(
        value["sha256"], "UNION_EXPECTED_MEMBER_DIFFERS")


def _outcomes(expected: Any, supplied: Any, label: str) -> tuple[str, list[str]]:
    _require(type(expected) is list and len(expected) <= MAX_MEMBERS, f"{label}_REQUIREMENTS_DIFFER")
    _require(type(supplied) is list and len(supplied) <= MAX_MEMBERS, f"{label}_OUTCOMES_DIFFER")
    expected_by_id = {}
    for row in expected:
        _keys(row, {"requirement_id", "required_status"}, f"{label}_REQUIREMENTS_DIFFER")
        rid = _text(row["requirement_id"], f"{label}_REQUIREMENTS_DIFFER")
        _require(rid not in expected_by_id and row["required_status"] in ("REQUIRED", "UNKNOWN"),
                 f"DUPLICATE_{label}_REQUIREMENT")
        expected_by_id[rid] = row
    actual_by_id = {}
    for row in supplied:
        _keys(row, {"requirement_id", "status", "evidence_digest"}, f"{label}_OUTCOMES_DIFFER")
        rid = _text(row["requirement_id"], f"{label}_OUTCOMES_DIFFER")
        _require(rid not in actual_by_id, f"DUPLICATE_{label}_OUTCOME")
        _require(row["status"] in ("PASS", "FAIL", "UNKNOWN"), f"{label}_OUTCOMES_DIFFER")
        _hash(row["evidence_digest"], f"{label}_OUTCOMES_DIFFER", optional=True)
        _require((row["status"] == "UNKNOWN") == (row["evidence_digest"] is None),
                 f"{label}_OUTCOMES_DIFFER")
        _require(row["status"] != "PASS", "UNQUALIFIED_DEPENDENCY_PASS")
        actual_by_id[rid] = row
    _require(set(expected_by_id) == set(actual_by_id), f"{label}_OUTCOME_SET_DIFFERS")
    failed = sorted(rid for rid, row in actual_by_id.items() if row["status"] == "FAIL")
    return ("FAIL" if failed else "UNKNOWN"), failed


def _union_members(authority: dict[str, Any], profile_coordinate: dict[str, Any]) -> dict[tuple, tuple]:
    _keys(authority, {"schema_version", "candidate_status", "completeness",
                      "consumer_source_coordinate", "families"}, "UNION_AUTHORITY_FIELDS")
    _require(authority["schema_version"] == UNION_AUTHORITY_SCHEMA
             and authority["candidate_status"] == "CANDIDATE"
             and authority["completeness"] == "UNKNOWN", "UNION_AUTHORITY_FIELDS")
    _require(authority["consumer_source_coordinate"] == profile_coordinate,
             "UNION_CONSUMER_SOURCE_COORDINATE_DIFFERS")
    _require(type(authority["families"]) is list, "UNION_AUTHORITY_FIELDS")
    result = {}
    families = set()
    for family in authority["families"]:
        _keys(family, {"family_id", "source_map_digest", "producer_source_coordinate",
                       "dependency_selection", "requirements"}, "UNION_AUTHORITY_FIELDS")
        fid = _text(family["family_id"], "UNION_AUTHORITY_FIELDS")
        _require(fid not in families, "DUPLICATE_UNION_FAMILY")
        families.add(fid)
        _hash(family["source_map_digest"], "UNION_AUTHORITY_FIELDS")
        _coordinate(family["producer_source_coordinate"], "UNION_AUTHORITY_FIELDS")
        _require(type(family["requirements"]) is list, "UNION_AUTHORITY_FIELDS")
        for row in family["requirements"]:
            _keys(row, {"object_kind", "tier", "member_id", "source", "claim_sha256"},
                  "UNION_EXPECTED_MEMBER_DIFFERS")
            key = (_text(row["object_kind"], "UNION_EXPECTED_MEMBER_DIFFERS"), row["tier"],
                   _text(row["member_id"], "UNION_EXPECTED_MEMBER_DIFFERS"))
            _require(type(row["tier"]) is int and 1 <= row["tier"] <= 9,
                     "UNION_EXPECTED_MEMBER_DIFFERS")
            _require(key not in result, "DUPLICATE_UNION_EXPECTED_MEMBER")
            result[key] = (fid, _source(row["source"]),
                           _hash(row["claim_sha256"], "UNION_EXPECTED_MEMBER_DIFFERS"))
    return result


def assess_application_authority_binding(*, requirements_bytes: bytes,
        applicability_claim_bytes: bytes, compiler_manifest_bytes: bytes,
        host_selection: ApplicationAuthorityHostSelection | None,
        observed_application_mechanism_digest: str,
        observed_compiler_mechanism_digest: str,
        observed_union_validator_digest: str) -> dict[str, Any]:
    """Bind exact candidate inventories without inventing scope-admission authority."""
    report = {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": "UNKNOWN",
        "binding_status": "UNKNOWN",
        "authority_status": "UNKNOWN",
        "child_status": "UNKNOWN",
        "interaction_status": "UNKNOWN",
        "semantic_completeness": "UNKNOWN",
        "full_application_status": "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "profile_digest": None,
        "requirements_digest": None,
        "union_authority_digest": None,
        "union_contributions_digest": None,
        "union_validation": None,
        "compiler_manifest_digest": None,
        "scope_admission_subject_digest": None,
        "scope_admission_replay": None,
        "semantic_completeness_subject_digest": None,
        "semantic_completeness_replay": None,
        "expected_instances": None,
        "expected_members": None,
        "blockers": [],
        "claim_boundary": (
            "Exact host-selected member, applicability, instance, source and mechanism binding. "
            "Only distinct installed, host-selected configured-key receipts can establish scope "
            "authority or selected semantic completeness. Human or legal authority, polish, "
            "acceptance and release remain separate."
        ),
    }
    try:
        _require(type(host_selection) is ApplicationAuthorityHostSelection,
                 "HOST_SELECTION_REQUIRED")
        host = host_selection
        for raw in (host.profile_bytes, host.union_authority_bytes, host.union_contributions_bytes):
            _require(type(raw) is bytes, "HOST_SELECTION_REQUIRED")
        if any(len(raw) > MAX_RECORD_BYTES for raw in (
                host.profile_bytes, host.union_authority_bytes,
                host.union_contributions_bytes)):
            raise _Unavailable("AUTHORITY_INPUT_CAPACITY_EXHAUSTED")
        for value, code in (
            (host.expected_profile_digest, "HOST_PROFILE_DIGEST_DIFFERS"),
            (host.expected_union_authority_digest, "UNION_AUTHORITY_DIGEST_DIFFERS"),
            (host.expected_union_contributions_digest, "UNION_CONTRIBUTIONS_DIGEST_DIFFERS"),
            (host.expected_consumer_source_coordinate_digest, "HOST_SOURCE_COORDINATE_DIGEST_DIFFERS"),
            (host.expected_application_mechanism_digest, "APPLICATION_MECHANISM_DIFFERS"),
            (host.expected_compiler_mechanism_digest, "COMPILER_MECHANISM_DIFFERS"),
            (host.expected_union_validator_digest, "UNION_VALIDATOR_DIFFERS"),
        ):
            _hash(value, code)
        _require(bytes_digest(host.profile_bytes) == host.expected_profile_digest,
                 "HOST_PROFILE_DIGEST_DIFFERS")
        _require(bytes_digest(host.union_authority_bytes) == host.expected_union_authority_digest,
                 "UNION_AUTHORITY_DIGEST_DIFFERS")
        _require(bytes_digest(host.union_contributions_bytes)
                 == host.expected_union_contributions_digest,
                 "UNION_CONTRIBUTIONS_DIGEST_DIFFERS")
        _coordinate(host.expected_consumer_source_coordinate, "HOST_SOURCE_COORDINATE_DIFFERS")
        _require(value_digest(host.expected_consumer_source_coordinate)
                 == host.expected_consumer_source_coordinate_digest,
                 "HOST_SOURCE_COORDINATE_DIGEST_DIFFERS")

        profile = _decode(host.profile_bytes, "AUTHORITY_PROFILE_FIELDS")
        profile_fields = {"schema_version", "profile_id", "profile_version", "core_profile_id",
            "root", "consumer_source_coordinate", "consumer_source_coordinate_digest",
            "application_mechanism_digest", "compiler_mechanism_digest", "union_validator_digest",
            "union_authority_digest", "union_contributions_digest", "compiler_manifest_digest",
            "scope_admission_subject_digest",
            "receipt_mode", "family_requirements", "member_requirements", "instance_requirements",
            "child_requirements", "interaction_requirements", "corrigibility_extension_status"}
        _keys(profile, profile_fields, "AUTHORITY_PROFILE_FIELDS")
        _require(profile["schema_version"] == AUTHORITY_PROFILE_SCHEMA,
                 "AUTHORITY_PROFILE_VERSION")
        _text(profile["profile_id"], "AUTHORITY_PROFILE_VERSION")
        _text(profile["profile_version"], "AUTHORITY_PROFILE_VERSION")
        _require(profile["core_profile_id"] == CORE_PROFILE, "CORE_PROFILE_DIFFERS")
        _require(profile["consumer_source_coordinate"] == host.expected_consumer_source_coordinate
                 and profile["consumer_source_coordinate_digest"]
                 == host.expected_consumer_source_coordinate_digest,
                 "CONSUMER_SOURCE_COORDINATE_DIFFERS")
        installed_application = installed_application_mechanism_digest()
        installed_compiler = installed_compiler_mechanism_digest()
        installed_union = installed_union_validator_digest()
        _require(profile["application_mechanism_digest"]
                 == host.expected_application_mechanism_digest
                 == _hash(observed_application_mechanism_digest, "APPLICATION_MECHANISM_DIFFERS")
                 == installed_application,
                 "APPLICATION_MECHANISM_DIFFERS")
        _require(profile["compiler_mechanism_digest"]
                 == host.expected_compiler_mechanism_digest
                 == _hash(observed_compiler_mechanism_digest, "COMPILER_MECHANISM_DIFFERS")
                 == installed_compiler,
                 "COMPILER_MECHANISM_DIFFERS")
        _require(profile["union_validator_digest"]
                 == host.expected_union_validator_digest
                 == _hash(observed_union_validator_digest, "UNION_VALIDATOR_DIFFERS")
                 == installed_union,
                 "UNION_VALIDATOR_DIFFERS")
        _require(profile["union_authority_digest"] == host.expected_union_authority_digest,
                 "UNION_AUTHORITY_DIGEST_DIFFERS")
        _require(profile["union_contributions_digest"] == host.expected_union_contributions_digest,
                 "UNION_CONTRIBUTIONS_DIGEST_DIFFERS")
        report["profile_digest"] = host.expected_profile_digest
        report["union_authority_digest"] = host.expected_union_authority_digest
        report["union_contributions_digest"] = host.expected_union_contributions_digest

        union = _decode(host.union_authority_bytes, "UNION_AUTHORITY_FIELDS")
        contributions = _decode_list(host.union_contributions_bytes,
                                     "UNION_CONTRIBUTIONS_FIELDS")
        union_validator = _load_union_validator()
        union_report = union_validator.validate_union(
            union,
            contributions,
            expected_authority_digest=value_digest(union),
            expected_source_coordinate=profile["consumer_source_coordinate"],
        )
        union_body = {key: value for key, value in union_report.items()
                      if key != "report_digest"}
        _require(union_report.get("report_digest") == value_digest(union_body),
                 "UNION_VALIDATION_REPORT_DIFFERS")
        report["union_validation"] = {
            "authority_digest": host.expected_union_authority_digest,
            "contributions_digest": host.expected_union_contributions_digest,
            "report_digest": union_report["report_digest"],
            "authority_binding": union_report.get("authority_binding"),
            "source_coordinate_binding": union_report.get("source_coordinate_binding"),
            "dependency_binding": union_report.get("dependency_binding"),
            "candidate_coverage": union_report.get("candidate_coverage"),
            "structural_union": union_report.get("structural_union"),
            "semantic_completeness": union_report.get("semantic_completeness"),
            "release_admissible": union_report.get("release_admissible"),
            "issue_codes": sorted({row.get("code", "INVALID_UNION_ISSUE")
                                   for row in union_report.get("issues", [])}),
        }
        union_clean = (
            union_report.get("authority_binding") == "MATCHED"
            and union_report.get("source_coordinate_binding") == "MATCHED"
            and union_report.get("dependency_binding") == "MATCHED"
            and union_report.get("candidate_coverage") == "MATCHED"
            and union_report.get("structural_union") == "PASS"
            and union_report.get("semantic_completeness") == "UNKNOWN"
            and union_report.get("release_admissible") is False
            and union_report.get("issues") == []
        )
        _require(union_clean, "UNION_VALIDATION_FAILED")
        union_members = _union_members(union, profile["consumer_source_coordinate"])

        compiler = _decode(compiler_manifest_bytes, "COMPILER_MANIFEST_FIELDS")
        report["compiler_manifest_digest"] = bytes_digest(compiler_manifest_bytes)
        _require(report["compiler_manifest_digest"] == profile["compiler_manifest_digest"],
                 "COMPILER_MANIFEST_DIGEST_DIFFERS")
        _require(compiler.get("schema_version") == COMPILER_SCHEMA
                 and compiler.get("mechanism_digest") == profile["compiler_mechanism_digest"],
                 "COMPILER_MANIFEST_FIELDS")
        _require(compiler.get("full_application_status") == "UNKNOWN"
                 and compiler.get("interaction_census_status") == "UNKNOWN"
                 and compiler.get("consumer_census_status") == "UNKNOWN"
                 and compiler.get("native_projection_status") == "UNKNOWN",
                 "COMPILER_UNKNOWN_BOUNDARY_DIFFERS")
        input_digests = compiler.get("input_digests")
        _require(type(input_digests) is dict and set(input_digests) == COMPILER_INPUT_NAMES
                 and all(_HASH.fullmatch(value) is not None
                         for value in input_digests.values() if type(value) is str)
                 and all(type(value) is str for value in input_digests.values()),
                 "COMPILER_INPUT_DIGESTS_DIFFER")
        _require(compiler.get("scope_kind") == FULL_SCOPE, "COMPILER_SCOPE_DIFFERS")
        closure = compiler.get("closure_certificate")
        closure_fields = {"schema_version", "scope_kind", "source_scope_digest",
            "input_digests", "mechanism_digest", "member_set_digests",
            "conservation_status", "complete_bounds", "full_application_status",
            "claim_boundary", "digest"}
        _keys(closure, closure_fields, "COMPILER_CLOSURE_CERTIFICATE_DIFFERS")
        member_set_digests = closure["member_set_digests"]
        _require(closure["schema_version"] == "verifier-application-census-closure-1"
                 and closure["scope_kind"] == FULL_SCOPE
                 and closure["source_scope_digest"] == input_digests["source_scope"]
                 and closure["input_digests"] == input_digests
                 and closure["mechanism_digest"] == installed_compiler
                 and type(member_set_digests) is dict
                 and set(member_set_digests) == COMPILER_MEMBER_SET_NAMES
                 and all(type(value) is str and _HASH.fullmatch(value) is not None
                         for value in member_set_digests.values())
                 and closure["conservation_status"] == "UNKNOWN"
                 and closure["complete_bounds"] is True
                 and closure["full_application_status"] == "UNKNOWN"
                 and type(closure["claim_boundary"]) is str
                 and bool(closure["claim_boundary"].strip()),
                 "COMPILER_CLOSURE_CERTIFICATE_DIFFERS")
        closure_body = {key: value for key, value in closure.items() if key != "digest"}
        _require(closure["digest"] == value_digest(closure_body),
                 "COMPILER_CLOSURE_CERTIFICATE_DIFFERS")
        admission = compiler.get("scope_admission")
        _keys(admission, {"authority_status", "subject", "admission_subject_digest"},
              "SCOPE_ADMISSION_DIFFERS")
        _require(admission["authority_status"] == "NOT_EVALUATED", "SCOPE_ADMISSION_DIFFERS")
        subject = admission.get("subject")
        expected_subject = {"schema_version": SCOPE_SUBJECT_SCHEMA,
            "operation": SCOPE_OPERATION, "scope_kind": compiler["scope_kind"],
            "closure_certificate_digest": closure["digest"],
            "input_digests": input_digests, "mechanism_digest": installed_compiler,
            "admitted_inapplicability": []}
        _require(subject == expected_subject, "SCOPE_ADMISSION_SUBJECT_DIFFERS")
        subject_digest = value_digest(subject)
        _require(admission.get("admission_subject_digest") == subject_digest
                 and profile["scope_admission_subject_digest"] == subject_digest,
                 "SCOPE_ADMISSION_SUBJECT_DIFFERS")
        report["scope_admission_subject_digest"] = subject_digest

        requirements = _decode(requirements_bytes, "CORE_REQUIREMENTS_FIELDS")
        report["requirements_digest"] = bytes_digest(requirements_bytes)
        _keys(requirements, {"schema_version", "profile_id", "root", "tiers", "families",
                             "instances", "extension"}, "CORE_REQUIREMENTS_FIELDS")
        _require(requirements["schema_version"] == CORE_REQUIREMENTS_SCHEMA
                 and requirements["profile_id"] == CORE_PROFILE
                 and requirements["root"] == profile["root"], "CORE_REQUIREMENTS_DIFFER")

        member_rows = profile["member_requirements"]
        _require(type(member_rows) is list and len(member_rows) <= MAX_MEMBERS,
                 "EXPECTED_MEMBER_FIELDS")
        expected_members = {}
        profile_union_members = {}
        member_fields = {"family_id", "object_kind", "tier", "member_id", "semantic_version",
            "objective", "proposition_digest", "source", "claim_sha256", "applicability",
            "inapplicability_basis_digest"}
        for row in member_rows:
            _keys(row, member_fields, "EXPECTED_MEMBER_FIELDS")
            key = (_text(row["object_kind"], "EXPECTED_MEMBER_FIELDS"), row["tier"],
                   _text(row["member_id"], "EXPECTED_MEMBER_FIELDS"))
            _require(key[0] in OBJECT_KINDS and type(key[1]) is int and 1 <= key[1] <= 9,
                     "EXPECTED_MEMBER_FIELDS")
            _require(key not in expected_members, "DUPLICATE_EXPECTED_MEMBER")
            _text(row["family_id"], "EXPECTED_MEMBER_FIELDS")
            _text(row["semantic_version"], "EXPECTED_MEMBER_FIELDS")
            _text(row["objective"], "EXPECTED_MEMBER_FIELDS")
            _hash(row["proposition_digest"], "EXPECTED_MEMBER_FIELDS")
            _hash(row["claim_sha256"], "EXPECTED_MEMBER_FIELDS")
            source = _source(row["source"])
            _require(row["applicability"] in ("REQUIRED", "NOT_APPLICABLE", "UNKNOWN"),
                     "EXPECTED_MEMBER_FIELDS")
            _hash(row["inapplicability_basis_digest"], "EXPECTED_MEMBER_FIELDS", optional=True)
            if row["applicability"] == "NOT_APPLICABLE":
                _require(row["inapplicability_basis_digest"] is not None,
                         "INAPPLICABILITY_BASIS_REQUIRED")
            else:
                _require(row["inapplicability_basis_digest"] is None,
                         "INAPPLICABILITY_BASIS_UNEXPECTED")
            expected_members[key] = row
            profile_union_members[key] = (row["family_id"], source, row["claim_sha256"])
        _require(profile_union_members == union_members, "UNION_EXPECTED_MEMBER_SET_DIFFERS")
        report["expected_members"] = len(expected_members)

        expected_instance_rows = profile["instance_requirements"]
        _require(type(expected_instance_rows) is list and len(expected_instance_rows) <= MAX_INSTANCES,
                 "EXPECTED_INSTANCE_FIELDS")
        expected_instances = {}
        expected_instance_fields = CORE_INSTANCE_FIELDS | {"object_kind", "member_id"}
        for row in expected_instance_rows:
            _keys(row, expected_instance_fields, "EXPECTED_INSTANCE_FIELDS")
            iid = _text(row["instance_id"], "EXPECTED_INSTANCE_FIELDS")
            _require(iid not in expected_instances, "DUPLICATE_EXPECTED_INSTANCE")
            member_key = (row["object_kind"], row["tier"], row["member_id"])
            member = expected_members.get(member_key)
            _require(member is not None and member["applicability"] == "REQUIRED"
                     and row["semantic_version"] == member["semantic_version"]
                     and row["objective"] == member["objective"]
                     and row["proposition_digest"] == member["proposition_digest"],
                     "EXPECTED_INSTANCE_MEMBER_DIFFERS")
            expected_instances[iid] = row
        report["expected_instances"] = len(expected_instances)
        for key, member in expected_members.items():
            count = sum(row["object_kind"] == key[0] and row["tier"] == key[1]
                        and row["member_id"] == key[2] for row in expected_instances.values())
            _require((member["applicability"] == "REQUIRED" and count > 0)
                     or (member["applicability"] != "REQUIRED" and count == 0),
                     "EXPECTED_MEMBER_INSTANCE_DENOMINATOR_DIFFERS")

        actual_rows = requirements["instances"]
        _require(type(actual_rows) is list and len(actual_rows) <= MAX_INSTANCES,
                 "CORE_INSTANCE_FIELDS")
        actual_instances = {}
        for row in actual_rows:
            _keys(row, CORE_INSTANCE_FIELDS, "CORE_INSTANCE_FIELDS")
            iid = _text(row["instance_id"], "CORE_INSTANCE_FIELDS")
            _require(iid not in actual_instances, "DUPLICATE_INSTANCE")
            actual_instances[iid] = row
        _require(set(actual_instances) == set(expected_instances), "INSTANCE_SET_DIFFERS")
        for iid, expected in expected_instances.items():
            _require(actual_instances[iid] == {field: expected[field] for field in CORE_INSTANCE_FIELDS},
                     "INSTANCE_BINDING_DIFFERS")

        family_rows = profile["family_requirements"]
        _require(type(family_rows) is list and len(family_rows) == 26 * 9,
                 "FAMILY_REQUIREMENT_SET_DIFFERS")
        expected_families = {}
        covered = set()
        for row in family_rows:
            _keys(row, {"object_kind", "tier", "applicability", "required_instances",
                        "inapplicability_basis_digest"},
                  "EXPECTED_FAMILY_FIELDS")
            key = (row["object_kind"], row["tier"])
            _require(key[0] in OBJECT_KINDS and type(key[1]) is int and 1 <= key[1] <= 9
                     and key not in expected_families, "DUPLICATE_EXPECTED_FAMILY")
            _require(row["applicability"] in ("REQUIRED", "NOT_APPLICABLE", "UNKNOWN")
                     and type(row["required_instances"]) is list,
                     "EXPECTED_FAMILY_FIELDS")
            _hash(row["inapplicability_basis_digest"], "EXPECTED_FAMILY_FIELDS", optional=True)
            if row["applicability"] == "NOT_APPLICABLE":
                _require(row["inapplicability_basis_digest"] is not None,
                         "INAPPLICABILITY_BASIS_REQUIRED")
            else:
                _require(row["inapplicability_basis_digest"] is None,
                         "INAPPLICABILITY_BASIS_UNEXPECTED")
            ids = row["required_instances"]
            _require(len(ids) == len(set(ids)) and all(iid in expected_instances for iid in ids)
                     and not set(ids) & covered, "EXPECTED_FAMILY_INSTANCE_DIFFERS")
            _require(all(expected_instances[iid]["object_kind"] == key[0]
                         and expected_instances[iid]["tier"] == key[1] for iid in ids),
                     "EXPECTED_FAMILY_INSTANCE_DIFFERS")
            _require((row["applicability"] == "REQUIRED" and bool(ids))
                     or (row["applicability"] != "REQUIRED" and not ids),
                     "EXPECTED_FAMILY_INSTANCE_DIFFERS")
            expected_families[key] = row
            covered.update(ids)
        _require(set(expected_families) == {(kind, tier) for kind in OBJECT_KINDS for tier in range(1, 10)}
                 and covered == set(expected_instances), "FAMILY_REQUIREMENT_SET_DIFFERS")

        actual_families = {}
        _require(type(requirements["families"]) is list, "CORE_FAMILY_FIELDS")
        for row in requirements["families"]:
            _keys(row, {"object_kind", "tier", "tier_name", "census", "required_instances"},
                  "CORE_FAMILY_FIELDS")
            key = (row["object_kind"], row["tier"])
            _require(key not in actual_families, "DUPLICATE_CORE_FAMILY")
            expected = expected_families.get(key)
            _require(expected is not None and row["tier_name"] == TIER_NAMES[key[1]]
                     and row["census"] == ("COMPLETE" if expected["applicability"] == "REQUIRED" else "UNKNOWN")
                     and type(row["required_instances"]) is list
                     and len(row["required_instances"]) == len(set(row["required_instances"]))
                     and set(row["required_instances"]) == set(expected["required_instances"]),
                     "CORE_FAMILY_BINDING_DIFFERS")
            actual_families[key] = row
        _require(set(actual_families) == set(expected_families), "CORE_FAMILY_SET_DIFFERS")

        actual_tiers = {}
        _require(type(requirements["tiers"]) is list and len(requirements["tiers"]) == 9,
                 "CORE_TIER_SET_DIFFERS")
        for row in requirements["tiers"]:
            _keys(row, {"tier", "tier_name", "census", "required_instances"}, "CORE_TIER_FIELDS")
            tier = row["tier"]
            _require(type(tier) is int and 1 <= tier <= 9 and tier not in actual_tiers,
                     "DUPLICATE_CORE_TIER")
            ids = [iid for iid, instance in expected_instances.items() if instance["tier"] == tier]
            _require(row["tier_name"] == TIER_NAMES[tier]
                     and row["census"] == ("COMPLETE" if ids else "UNKNOWN")
                     and type(row["required_instances"]) is list
                     and len(row["required_instances"]) == len(set(row["required_instances"]))
                     and set(row["required_instances"]) == set(ids), "CORE_TIER_BINDING_DIFFERS")
            actual_tiers[tier] = row
        _require(set(actual_tiers) == set(range(1, 10)), "CORE_TIER_SET_DIFFERS")

        extension = requirements["extension"]
        _require(type(extension) is dict
                 and extension.get("schema_version") == CORRIGIBILITY_EXTENSION
                 and extension.get("profile_id") == CORRIGIBILITY_EXTENSION
                 and extension.get("declared_status") in ("WIP", "UNKNOWN")
                 and extension.get("declared_status") == profile["corrigibility_extension_status"],
                 "CORRIGIBILITY_EXTENSION_DIFFERS")

        claim = _decode(applicability_claim_bytes, "APPLICABILITY_CLAIM_FIELDS")
        _keys(claim, {"schema_version", "authority_profile_digest", "requirements_digest",
                      "family_decisions", "member_decisions", "child_outcomes",
                      "interaction_outcomes"}, "APPLICABILITY_CLAIM_FIELDS")
        _require(claim["schema_version"] == APPLICABILITY_CLAIM_SCHEMA
                 and claim["authority_profile_digest"] == host.expected_profile_digest,
                 "APPLICABILITY_AUTHORITY_PROFILE_DIFFERS")
        _require(claim["requirements_digest"] == report["requirements_digest"],
                 "APPLICABILITY_REQUIREMENTS_DIGEST_DIFFERS")

        family_decisions = {}
        _require(type(claim["family_decisions"]) is list, "FAMILY_DECISION_FIELDS")
        for row in claim["family_decisions"]:
            _keys(row, {"object_kind", "tier", "applicability"}, "FAMILY_DECISION_FIELDS")
            key = (row["object_kind"], row["tier"])
            _require(key not in family_decisions, "DUPLICATE_FAMILY_DECISION")
            family_decisions[key] = row["applicability"]
        _require(set(family_decisions) == set(expected_families), "FAMILY_DECISION_SET_DIFFERS")
        _require(all(family_decisions[key] == row["applicability"]
                     for key, row in expected_families.items()), "FAMILY_APPLICABILITY_DIFFERS")

        member_decisions = {}
        _require(type(claim["member_decisions"]) is list, "MEMBER_DECISION_FIELDS")
        for row in claim["member_decisions"]:
            _keys(row, {"object_kind", "tier", "member_id", "applicability"},
                  "MEMBER_DECISION_FIELDS")
            key = (row["object_kind"], row["tier"], row["member_id"])
            _require(key not in member_decisions, "DUPLICATE_MEMBER_DECISION")
            member_decisions[key] = row["applicability"]
        _require(set(member_decisions) == set(expected_members), "MEMBER_DECISION_SET_DIFFERS")
        _require(all(member_decisions[key] == row["applicability"]
                     for key, row in expected_members.items()), "MEMBER_APPLICABILITY_DIFFERS")

        report["child_status"], child_failures = _outcomes(
            profile["child_requirements"], claim["child_outcomes"], "CHILD")
        report["interaction_status"], interaction_failures = _outcomes(
            profile["interaction_requirements"], claim["interaction_outcomes"], "INTERACTION")

        not_applicable = ([key for key, row in expected_members.items()
                           if row["applicability"] == "NOT_APPLICABLE"]
                          + [key for key, row in expected_families.items()
                             if row["applicability"] == "NOT_APPLICABLE"])
        _require(profile["receipt_mode"] in ("NO_INAPPLICABILITY",
                                             "QUALIFIED_SCOPE_ADMISSION_REQUIRED"),
                 "RECEIPT_MODE_DIFFERS")
        if profile["receipt_mode"] == "NO_INAPPLICABILITY":
            _require(not not_applicable, "UNAUTHORIZED_NOT_APPLICABLE")
        else:
            _require(bool(not_applicable), "RECEIPT_MODE_DIFFERS")

        report["binding_status"] = "PASS"
        if child_failures:
            report["blockers"].append("CHILD_REQUIREMENT_FAILED")
        if interaction_failures:
            report["blockers"].append("INTERACTION_REQUIREMENT_FAILED")
        if child_failures or interaction_failures:
            report["status"] = "FAIL"

        receipt = host.scope_admission_receipt_bytes
        expected_receipt = host.expected_scope_admission_receipt_digest
        scope_selection = host.scope_admission_replay
        if scope_selection is None:
            if receipt is None:
                _require(expected_receipt is None, "SCOPE_ADMISSION_RECEIPT_DIGEST_DIFFERS")
                report["blockers"].append("QUALIFIED_SCOPE_ADMISSION_RECEIPT_UNAVAILABLE")
            else:
                _require(type(receipt) is bytes and len(receipt) <= MAX_RECORD_BYTES,
                         "SCOPE_ADMISSION_RECEIPT_FIELDS")
                _hash(expected_receipt, "SCOPE_ADMISSION_RECEIPT_DIGEST_DIFFERS")
                _require(bytes_digest(receipt) == expected_receipt,
                         "SCOPE_ADMISSION_RECEIPT_DIGEST_DIFFERS")
                report["blockers"].append(
                    "QUALIFIED_SCOPE_ADMISSION_RECEIPT_REPLAY_UNAVAILABLE")
        else:
            _require(type(scope_selection) is QualifiedAuthorityReplaySelection,
                     "SCOPE_ADMISSION_REPLAY_SELECTION_DIFFERS")
            _require(receipt == scope_selection.receipt_bytes
                     and expected_receipt == scope_selection.expected_receipt_digest,
                     "SCOPE_ADMISSION_RECEIPT_SELECTION_DIFFERS")
            scope_result = replay_qualified_authority_receipt(
                scope_selection,
                required_operation=SCOPE_OPERATION,
                required_subject_digest=subject_digest,
            )
            report["scope_admission_replay"] = scope_result
            report["authority_status"] = scope_result["status"]
            if scope_result["status"] == "FAIL":
                report["status"] = "FAIL"
            if scope_result["status"] != "PASS":
                report["blockers"].extend(scope_result["blockers"])
                report["blockers"].append(
                    "QUALIFIED_SCOPE_ADMISSION_RECEIPT_NOT_ESTABLISHED")

        semantic_selection = host.semantic_completeness_replay
        if semantic_selection is None:
            report["blockers"].append("SEMANTIC_COMPLETENESS_RECEIPT_UNAVAILABLE")
        elif report["authority_status"] == "PASS":
            _require(type(semantic_selection) is QualifiedAuthorityReplaySelection,
                     "SEMANTIC_COMPLETENESS_REPLAY_SELECTION_DIFFERS")
            semantic_subject = semantic_completeness_subject(
                profile_digest=report["profile_digest"],
                requirements_digest=report["requirements_digest"],
                union_authority_digest=report["union_authority_digest"],
                union_contributions_digest=report["union_contributions_digest"],
                compiler_manifest_digest=report["compiler_manifest_digest"],
                scope_admission_subject_digest=subject_digest,
                scope_admission_receipt_digest=scope_selection.expected_receipt_digest,
                consumer_source_coordinate_digest=(
                    host.expected_consumer_source_coordinate_digest),
                application_mechanism_digest=host.expected_application_mechanism_digest,
                compiler_mechanism_digest=host.expected_compiler_mechanism_digest,
                union_validator_digest=host.expected_union_validator_digest,
            )
            semantic_subject_digest = value_digest(semantic_subject)
            report["semantic_completeness_subject_digest"] = semantic_subject_digest
            if semantic_selection.expected_operation != SEMANTIC_COMPLETENESS_OPERATION:
                semantic_result = {
                    "schema_version": AUTHORITY_REPLAY_SCHEMA,
                    "status": "FAIL",
                    "replay_status": "REJECTED",
                    "operation": SEMANTIC_COMPLETENESS_OPERATION,
                    "subject_digest": semantic_subject_digest,
                    "receipt_digest": None,
                    "policy_digest": None,
                    "approving_actors": [],
                    "blockers": ["SEMANTIC_COMPLETENESS_OPERATION_DIFFERS"],
                    "claim_boundary": (
                        "Scope admission cannot be cast as semantic completeness."),
                }
                semantic_result["replay_digest"] = value_digest(semantic_result)
            else:
                semantic_result = replay_qualified_authority_receipt(
                    semantic_selection,
                    required_operation=SEMANTIC_COMPLETENESS_OPERATION,
                    required_subject_digest=semantic_subject_digest,
                )
            report["semantic_completeness_replay"] = semantic_result
            report["semantic_completeness"] = semantic_result["status"]
            if semantic_result["status"] == "FAIL":
                report["status"] = "FAIL"
            if semantic_result["status"] != "PASS":
                report["blockers"].extend(semantic_result["blockers"])
        else:
            report["blockers"].append("SEMANTIC_COMPLETENESS_SCOPE_AUTHORITY_REQUIRED")

        if report["child_status"] == "UNKNOWN":
            report["blockers"].append("CHILD_REQUIREMENTS_UNKNOWN")
        if report["interaction_status"] == "UNKNOWN":
            report["blockers"].append("INTERACTION_REQUIREMENTS_UNKNOWN")
        if report["semantic_completeness"] != "PASS":
            report["blockers"].append("SEMANTIC_COMPLETENESS_UNKNOWN")
    except _Unavailable as exc:
        report["blockers"].append(str(exc))
    except (MemoryError, RecursionError, OverflowError):
        known_fail = (
            report["status"] == "FAIL"
            or report["child_status"] == "FAIL"
            or report["interaction_status"] == "FAIL"
        )
        report["status"] = "FAIL" if known_fail else "UNKNOWN"
        report["binding_status"] = "FAIL" if known_fail else "UNKNOWN"
        if report["child_status"] == "FAIL":
            report["blockers"].append("CHILD_REQUIREMENT_FAILED")
        if report["interaction_status"] == "FAIL":
            report["blockers"].append("INTERACTION_REQUIREMENT_FAILED")
        report["blockers"].append("AUTHORITY_CHECKING_RESOURCE_UNAVAILABLE")
    except (_Refuted, KeyError, TypeError, ValueError, UnicodeError) as exc:
        report["status"] = "FAIL"
        report["binding_status"] = "FAIL"
        report["blockers"].append(str(exc) if isinstance(exc, _Refuted)
                                  else "AUTHORITY_BINDING_CONTRACT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]))
    report["assessment_digest"] = value_digest(report)
    return report


__all__ = [
    "APPLICABILITY_CLAIM_SCHEMA", "ASSESSMENT_SCHEMA", "AUTHORITY_APPROVAL_SCHEMA",
    "AUTHORITY_POLICY_SCHEMA", "AUTHORITY_PROFILE_SCHEMA", "AUTHORITY_RECEIPT_SCHEMA",
    "AUTHORITY_REPLAY_SCHEMA", "AUTHORITY_SIGNATURE_SCHEMA", "AUTHORITY_STATUS_SCHEMA",
    "ApplicationAuthorityHostSelection", "QualifiedAuthorityReplaySelection",
    "CORE_PROFILE", "CORE_REQUIREMENTS_SCHEMA", "CORRIGIBILITY_EXTENSION",
    "SEMANTIC_COMPLETENESS_OPERATION", "SEMANTIC_COMPLETENESS_SUBJECT_SCHEMA",
    "SCOPE_OPERATION", "TIER_NAMES", "UNION_AUTHORITY_SCHEMA",
    "assess_application_authority_binding", "authority_signing_bytes", "bytes_digest",
    "canonical_bytes", "qualified_authority_mechanism_digest",
    "replay_qualified_authority_receipt", "semantic_completeness_subject",
    "installed_application_mechanism_digest", "installed_compiler_mechanism_digest",
    "installed_union_validator_digest", "mechanism_digest", "text_digest", "value_digest",
]
