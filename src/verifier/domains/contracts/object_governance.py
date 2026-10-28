"""Exact-kind selected namespace-admission governance certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Ed25519 is the Edwards-curve digital signature
algorithm with a 255-bit field. Time is integer Coordinated Universal Time
(UTC) Unix seconds; counts are dimensionless and encoded limits are bytes.
Configured public keys do not establish real-world authority or legal status.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core import signature_keys
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OBJECT-8.1"
REQUEST_VERSION = "verifier-current-object-governance-request-1"
POLICY_VERSION = "verifier-current-object-governance-policy-1"
EVIDENCE_VERSION = "verifier-current-object-governance-evidence-1"
DECISION_VERSION = "verifier-current-object-governance-decision-1"
STATUS_VERSION = "verifier-current-object-governance-status-1"
ENVELOPE_VERSION = "verifier-current-object-governance-envelope-1"
CERTIFICATE_VERSION = "verifier-current-object-governance-certificate-1"
MECHANISM_ID = "verifier.current-object.namespace-governance.1"
SCOPE = "selected_signed_namespace_admission_quorum"
_PREFIX = b"vstd-object-governance-ed25519-1\0"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")
_HEX_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_MAX_TIME = 2**53 - 1
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_CERTIFICATE_BYTES = 4 * 1024 * 1024


class ObjectGovernanceError(ValueError):
    """Invalid external selection or substituted certificate."""


class _SignatureBackendUnavailable(Unavailable):
    """The selected public signature cannot be checked in this environment."""


def _kind(value: Any) -> str:
    if type(value) is not str or value not in {kind.value for kind in ObjectKind}:
        raise ObjectGovernanceError("exact admitted object kind required")
    return value


def coordinate(kind: str) -> str:
    """Select one narrow governance coordinate for an exact namespace kind."""
    return _kind(kind) + "-8.1"


def registration(kind: str = "OBJECT") -> dict[str, Any]:
    """Describe signed namespace admission, not all governance for this kind."""
    kind = _kind(kind)
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind),
        "subject_kind": kind,
        "scope": SCOPE,
        "proposition": (
            "Under the independently selected revisioned public-key policy "
            f"and evaluation time, the exact retained {kind} namespace record "
            "has a configured quorum of distinct signed approvals for its "
            "selected namespace admission action, no selected veto or revoked "
            "decision, and a separately signed fresh revocation view."
        ),
        "prerequisites": [
            f"externally selected exact {kind} record digest, namespace, "
            "policy, trusted evaluation time and retained signed evidence"
        ],
        "exclusions": [
            "policy issuer authenticity, clock source authenticity, human consent",
            "legal or moral compliance, actual namespace admission or enforcement",
            "registry completeness, operand target truth, whole governance tier",
            f"{kind} profile, privacy and security conclusions",
        ],
    }


def proposition_digest(kind: str) -> str:
    """Bind the exact kind-specific proposition, independently of the record."""
    return "sha256:" + canonical_digest(registration(kind))


PROPOSITION_DIGEST = proposition_digest("OBJECT")


@dataclass(frozen=True)
class GovernanceDescriptor:
    """Public route metadata for one bounded governance objective."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


@dataclass(frozen=True)
class KindGovernanceDescriptor(GovernanceDescriptor):
    """Kind-specific metadata; the original OBJECT descriptor stays compatible."""

    kind: str

    def __post_init__(self) -> None:
        _kind(self.kind)

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.kind)


def _digest(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ObjectGovernanceError("canonical SHA-256 commitment required")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ObjectGovernanceError("bounded nonempty text required")
    return value


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_TIME:
        raise ObjectGovernanceError("bounded integer UTC second required")
    return value


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields):
        raise ObjectGovernanceError(label + " fields differ")
    if any(type(key) is not str for key in value):
        raise ObjectGovernanceError(label + " fields differ")
    if set(value) != fields:
        raise ObjectGovernanceError(label + " fields differ")
    return dict(value)


def _public_key(value: Any) -> bytes:
    if type(value) is not str or _HEX_KEY.fullmatch(value) is None:
        raise ObjectGovernanceError("canonical Ed25519 public key required")
    try:
        return signature_keys.admit_ed25519_public_key(bytes.fromhex(value))
    except ValueError as exc:
        raise ObjectGovernanceError("public key is not admitted") from exc


def mechanism_digest() -> str:
    """Bind direct checking code and the installed objective statement."""
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, signature_keys, common_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_OBJECT_GOVERNANCE.md"] = (
        Path(__file__).parents[2] / "standard" / "CURRENT_OBJECT_GOVERNANCE.md")
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest", "namespace_id",
        "policy_id", "revision", "decision_keys", "status_key", "quorum",
        "valid_from", "valid_until", "max_status_age_seconds",
        "max_certificate_bytes",
    }, "policy")
    if (type(selected["schema_version"]) is not str
            or type(selected["mechanism_id"]) is not str
            or selected["schema_version"] != POLICY_VERSION
            or selected["mechanism_id"] != MECHANISM_ID
            or _digest(selected["mechanism_digest"]) != mechanism_digest()):
        raise ObjectGovernanceError("selected policy mechanism differs")
    _text(selected["namespace_id"])
    _text(selected["policy_id"])
    if type(selected["revision"]) is not int or not 1 <= selected["revision"] <= _MAX_TIME:
        raise ObjectGovernanceError("positive bounded policy revision required")
    keys = selected["decision_keys"]
    if type(keys) is not list or not 1 <= len(keys) <= 16:
        raise ObjectGovernanceError("bounded decision key inventory required")
    actors: set[str] = set()
    key_ids: set[str] = set()
    public_keys: set[bytes] = set()
    for row in keys:
        admitted = _record(row, {"actor_id", "key_id", "public_key"}, "decision key")
        actor_id, key_id = _text(admitted["actor_id"]), _text(admitted["key_id"])
        public_key = _public_key(admitted["public_key"])
        if actor_id in actors or key_id in key_ids or public_key in public_keys:
            raise ObjectGovernanceError("decision authorities must be distinct")
        actors.add(actor_id)
        key_ids.add(key_id)
        public_keys.add(public_key)
    if [row["actor_id"] for row in keys] != sorted(actors):
        raise ObjectGovernanceError("decision authorities require canonical order")
    status = _record(selected["status_key"], {"key_id", "public_key"}, "status key")
    _text(status["key_id"])
    status_public = _public_key(status["public_key"])
    if status["key_id"] in key_ids or status_public in public_keys:
        raise ObjectGovernanceError("revocation authority must use a separate key")
    if type(selected["quorum"]) is not int or not 1 <= selected["quorum"] <= len(keys):
        raise ObjectGovernanceError("configured quorum is unavailable")
    beginning, end = _time(selected["valid_from"]), _time(selected["valid_until"])
    if beginning >= end:
        raise ObjectGovernanceError("policy interval is empty")
    age = selected["max_status_age_seconds"]
    if type(age) is not int or not 1 <= age <= 86400:
        raise ObjectGovernanceError("status age bound is unsupported")
    size = selected["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ObjectGovernanceError("certificate byte bound is unsupported")
    selected["decision_keys"] = [dict(row) for row in keys]
    selected["status_key"] = dict(status)
    return selected


def governance_policy(*, namespace_id: str, policy_id: str, revision: int,
                      decision_keys: list[dict[str, str]],
                      status_key: dict[str, str], quorum: int,
                      valid_from: int, valid_until: int,
                      max_status_age_seconds: int = 60,
                      max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format external public policy; the caller must authenticate its source."""
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "namespace_id": namespace_id,
        "policy_id": policy_id, "revision": revision,
        "decision_keys": decision_keys, "status_key": status_key, "quorum": quorum,
        "valid_from": valid_from, "valid_until": valid_until,
        "max_status_age_seconds": max_status_age_seconds,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "object_id", "record_digest", "namespace_id", "action",
        "evaluation_time", "evidence_ref", "policy_digest",
    }, "request")
    kind = _kind(selected["object_kind"])
    for field, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", coordinate(kind)),
        ("proposition_digest", proposition_digest(kind)),
        ("action", "NAMESPACE_ADMIT"),
    ):
        if type(selected[field]) is not str or selected[field] != expected:
            raise ObjectGovernanceError("selected objective differs")
    _text(selected["object_id"])
    _text(selected["namespace_id"])
    _time(selected["evaluation_time"])
    for field in ("record_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    return selected


def governance_request(item: NamespaceObject, *, namespace_id: str,
                       evidence_ref: str, evaluation_time: int,
                       policy: dict[str, Any]) -> dict[str, Any]:
    """Select the actual canonical record kind; never coerce it to OBJECT."""
    admitted = _policy(policy)
    if type(item) is not NamespaceObject:
        raise ObjectGovernanceError("exact namespace record required")
    kind = item.kind.value
    if namespace_id != admitted["namespace_id"]:
        raise ObjectGovernanceError("selected namespace differs from policy")
    if len(canonical_bytes(item.to_dict())) > _MAX_EVIDENCE_BYTES:
        raise ObjectGovernanceError("selected record exceeds byte bound")
    return _request({
        "schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": coordinate(kind),
        "proposition_digest": proposition_digest(kind), "object_kind": kind,
        "object_id": item.object_id, "record_digest": item.digest,
        "namespace_id": namespace_id, "action": "NAMESPACE_ADMIT",
        "evaluation_time": evaluation_time, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
    })


def signing_bytes(role: str, key_id: str, payload: dict[str, Any]) -> bytes:
    """Return domain-separated exact signing bytes; no private key is loaded."""
    if role not in ("decision", "status") or type(role) is not str:
        raise ObjectGovernanceError("unsupported governance signature role")
    _text(key_id)
    if type(payload) is not dict:
        raise ObjectGovernanceError("signed payload must be an object")
    encoded = canonical_bytes({"schema_version": ENVELOPE_VERSION,
                               "role": role, "key_id": key_id, "payload": payload})
    if len(encoded) > _MAX_EVIDENCE_BYTES:
        raise ObjectGovernanceError("signed payload exceeds byte bound")
    return _PREFIX + encoded


def _envelope_constraints(value: Any, key_id: str) -> dict[str, Any]:
    """Admit represented envelope grammar; authenticate no signature."""
    try:
        envelope = _record(value, {
            "schema_version", "key_id", "payload", "signature"}, "signed envelope")
    except ObjectGovernanceError as exc:
        raise Refuted(str(exc)) from exc
    if (envelope["schema_version"] != ENVELOPE_VERSION
            or envelope["key_id"] != key_id
            or type(envelope["payload"]) is not dict
            or type(envelope["signature"]) is not str
            or _HEX_SIGNATURE.fullmatch(envelope["signature"]) is None):
        raise Refuted("signed envelope version, key or signature differs")
    return envelope


def _verify_envelope(value: Any, *, role: str, key_id: str,
                     public_key: bytes) -> dict[str, Any]:
    envelope = _envelope_constraints(value, key_id)
    try:
        message = signing_bytes(role, key_id, envelope["payload"])
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise _SignatureBackendUnavailable(
            "public signature backend is unavailable") from exc
    except ObjectGovernanceError as exc:
        raise Refuted(str(exc)) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(envelope["signature"]), message)
    except UnsupportedAlgorithm as exc:
        raise _SignatureBackendUnavailable(
            "public signature algorithm is unavailable") from exc
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise Refuted("configured public signature does not verify") from exc
    return envelope["payload"]


def _payload(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    try:
        return _record(value, fields, label)
    except ObjectGovernanceError as exc:
        raise Refuted(str(exc)) from exc


def _evidence(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > _MAX_EVIDENCE_BYTES:
        raise ObjectGovernanceError("retained evidence exceeds byte bound")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
        if canonical_bytes(value) != raw:
            raise ObjectGovernanceError("retained evidence is noncanonical")
        selected = _record(value, {
            "schema_version", "record", "decisions", "status"}, "evidence")
        if selected["schema_version"] != EVIDENCE_VERSION:
            raise ObjectGovernanceError("unsupported governance evidence version")
        if type(selected["decisions"]) is not list or len(selected["decisions"]) > 16:
            raise ObjectGovernanceError("bounded decision inventory required")
        if selected["status"] is not None and type(selected["status"]) is not dict:
            raise ObjectGovernanceError("signed status or absence required")
        return selected
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ObjectGovernanceError):
            raise
        raise ObjectGovernanceError("governance evidence is malformed") from exc


def _decision_constraints(value: Any, configured: dict[str, Any],
                          request: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Check necessary represented constraints; authenticate no signature."""
    decision = _payload(value, {
        "schema_version", "decision_id", "actor_id", "policy_digest",
        "record_digest", "namespace_id", "action", "vote",
        "issued_at", "expires_at"}, "decision")
    if (decision["schema_version"] != DECISION_VERSION
            or decision["actor_id"] != configured["actor_id"]
            or decision["policy_digest"] != request["policy_digest"]
            or decision["record_digest"] != request["record_digest"]
            or decision["namespace_id"] != request["namespace_id"]
            or decision["action"] != request["action"]):
        raise Refuted("retained decision differs from selected action")
    try:
        identifier = _text(decision["decision_id"])
        issued, expires = _time(decision["issued_at"]), _time(decision["expires_at"])
    except ObjectGovernanceError as exc:
        raise Refuted(str(exc)) from exc
    now = request["evaluation_time"]
    if issued > now or expires <= issued or expires <= now:
        raise Refuted("retained decision is not current")
    if decision["vote"] == "VETO":
        raise Refuted("selected retained veto prevents admission")
    if decision["vote"] != "APPROVE":
        raise Refuted("unsupported retained decision")
    return decision, identifier


def _status_constraints(value: Any, request: dict[str, Any],
                        policy: dict[str, Any],
                        selected_decisions: set[str]) -> tuple[dict[str, Any], bool]:
    """Refuse necessary represented constraints; authenticate no revocation."""
    status = _payload(value, {
        "schema_version", "policy_digest", "as_of", "expires_at",
        "revoked_decision_ids"}, "status")
    if (status["schema_version"] != STATUS_VERSION
            or status["policy_digest"] != request["policy_digest"]):
        raise Refuted("retained revocation view differs from selected policy")
    try:
        as_of, expires = _time(status["as_of"]), _time(status["expires_at"])
    except ObjectGovernanceError as exc:
        raise Refuted(str(exc)) from exc
    now = request["evaluation_time"]
    if as_of > now or expires <= as_of:
        raise Refuted("retained revocation time order is invalid")
    if expires <= now or now - as_of > policy["max_status_age_seconds"]:
        # Preserve freshness UNKNOWN precedence over revocation predicates.
        # The caller defers this unavailability until decision authentication.
        return status, False
    revoked = status["revoked_decision_ids"]
    if (type(revoked) is not list or len(revoked) > 256
            or any(type(value) is not str or not value.strip() or len(value) > 256
                   for value in revoked)
            or revoked != sorted(set(revoked))):
        raise Refuted("retained revocation identifiers are malformed")
    if selected_decisions.intersection(revoked):
        raise Refuted("selected decision occurs in retained fresh revocation view")
    return status, True


def _evaluate(request: dict[str, Any], policy: dict[str, Any],
              retained: bytes) -> dict[str, Any]:
    evidence = _evidence(retained)
    record = _payload(evidence["record"],
                      {"object_id", "kind", "payload", "operands"}, "object record")
    if (type(record["payload"]) is not dict or type(record["operands"]) is not dict):
        raise Refuted("retained object payload or operands are malformed")
    try:
        item = NamespaceObject.create(
            record["object_id"], record["kind"], record["payload"],
            record["operands"])
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refuted("retained namespace record is invalid") from exc
    if (item.to_dict() != record or item.kind.value != request["object_kind"]
            or item.object_id != request["object_id"]
            or item.digest != request["record_digest"]):
        raise Refuted("retained record or kind differs from selected subject")
    now = request["evaluation_time"]
    if (request["namespace_id"] != policy["namespace_id"]
            or not policy["valid_from"] <= now < policy["valid_until"]):
        raise Refuted("selected namespace or policy interval differs")
    # This finite selected list bounds possible approvals without authenticating
    # any envelope. A shortfall refutes the conjunction even if signatures
    # cannot be checked; sufficient cardinality proves no approval validity.
    if len(evidence["decisions"]) < policy["quorum"]:
        raise Refuted("selected decision inventory cannot reach quorum")
    keys = {row["key_id"]: row for row in policy["decision_keys"]}
    # Repeated configured keys cannot identify distinct approving actors.
    # Shape, membership and repetition are decidable before signature imports;
    # admitting this inventory does not authenticate a single approval.
    # A valid signature cannot repair false binding/currentness/approval
    # predicates; an invalid signature also refutes this conjunction. Inspect
    # all selected payloads before any missing dependency can mask a refutation.
    selected_decisions: set[str] = set()
    selected_signers: set[str] = set()
    for envelope in evidence["decisions"]:
        if type(envelope) is not dict:
            raise Refuted("decision envelope is malformed")
        key_id = envelope.get("key_id")
        if type(key_id) is not str or key_id not in keys:
            raise Refuted("decision signer is not configured")
        if key_id in selected_signers:
            raise Refuted("duplicate configured decision signer")
        selected_signers.add(key_id)
        _, identifier = _decision_constraints(
            envelope.get("payload"), keys[key_id], request)
        if identifier in selected_decisions:
            raise Refuted("duplicate selected decision identifier")
        selected_decisions.add(identifier)
    if evidence["status"] is not None:
        # Missing/stale status must not hide decision-signature refutations.
        # This pure pass raises only independently decidable refusals.
        status_envelope = _envelope_constraints(
            evidence["status"], policy["status_key"]["key_id"])
        _status_constraints(status_envelope["payload"], request,
                            policy, selected_decisions)
    seen_actors: set[str] = set()
    seen_decisions: set[str] = set()
    approvals = 0
    for envelope in evidence["decisions"]:
        if type(envelope) is not dict:
            raise Refuted("decision envelope is malformed")
        key_id = envelope.get("key_id")
        if type(key_id) is not str or key_id not in keys:
            raise Refuted("decision signer is not configured")
        configured = keys[key_id]
        decision = _verify_envelope(
            envelope, role="decision", key_id=key_id,
            public_key=bytes.fromhex(configured["public_key"]))
        decision, identifier = _decision_constraints(decision, configured, request)
        actor = decision["actor_id"]
        if identifier in seen_decisions or actor in seen_actors:
            raise Refuted("duplicate decision or approving actor")
        seen_decisions.add(identifier)
        seen_actors.add(actor)
        approvals += 1
    if approvals < policy["quorum"]:
        raise Refuted("selected signed approvals do not reach quorum")
    if evidence["status"] is None:
        raise Unavailable("signed revocation view is unavailable")
    status_key = policy["status_key"]
    status = _verify_envelope(
        evidence["status"], role="status", key_id=status_key["key_id"],
        public_key=bytes.fromhex(status_key["public_key"]))
    status, fresh = _status_constraints(status, request, policy, seen_decisions)
    if not fresh:
        raise Unavailable("signed revocation view is stale")
    as_of = status["as_of"]
    return {"approvals": approvals, "quorum": policy["quorum"],
            "status_as_of": as_of, "policy_revision": policy["revision"]}


class _GovernanceMechanism:
    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_id = MECHANISM_ID
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, _binding: BoundProposition,
                 evidence: tuple[bytes, ...]) -> MechanismDecision:
        try:
            if len(evidence) != 1:
                raise Unavailable("one retained governance evidence item required")
            observations = _evaluate(self.request, self.policy, evidence[0])
            return MechanismDecision(MechanismOutcome.PASS,
                'configured signed quorum and fresh status admit selected ' + self.request["object_kind"],
                observations)
        except _SignatureBackendUnavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc),
                {"checking_dependency": "SIGNATURE_BACKEND_UNAVAILABLE"})
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (Refuted, ObjectGovernanceError, ValueError, TypeError,
                KeyError, UnicodeError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ObjectGovernanceError("request differs from external policy")
    proposition = BoundProposition(
        subject_id=request["object_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=(policy["policy_id"],),
        bounds=EvidenceBounds(1, _MAX_EVIDENCE_BYTES),
        parameters={"request": request, "policy_digest": request["policy_digest"]})
    session = VerificationSession(store)
    session.register(_GovernanceMechanism(request, policy))
    evaluation = session.evaluate(proposition)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "proposition_digest": request["proposition_digest"],
        "scope": SCOPE, "object_kind": request["object_kind"],
        "object_id": request["object_id"],
        "record_digest": request["record_digest"],
        "namespace_id": request["namespace_id"],
        "policy_revision": policy["revision"],
        "selected_key_authority": "EXTERNAL_POLICY",
        "legal_compliance": "NOT_ESTABLISHED",
        "human_consent": "NOT_ESTABLISHED",
        "enforcement": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["certificate_digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ObjectGovernanceError("certificate byte bound exhausted")
    return encoded


def build_governance_certificate(request: dict[str, Any],
                                 evidence_bytes: bytes | None, *,
                                 policy: dict[str, Any]) -> bytes:
    """Retain selected evidence and issue one bounded computational result."""
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        _evidence(evidence_bytes)
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ObjectGovernanceError("retained evidence differs from selection")
    return _build(selected, admitted, store)


def recheck_governance_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    """Rebuild exact certificate under separately selected request and policy."""
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes or not certificate_bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ObjectGovernanceError("certificate exceeds selected byte bound")
    try:
        value = strict_json_loads(certificate_bytes.decode("utf-8"))
        if canonical_bytes(value) != certificate_bytes:
            raise ObjectGovernanceError("certificate is noncanonical")
        envelope = _record(value, {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result",
            "certificate_digest"}, "certificate")
        if envelope["schema_version"] != CERTIFICATE_VERSION:
            raise ObjectGovernanceError("certificate version differs")
        if (envelope["certificate_digest"] != "sha256:" + canonical_digest({
                key: item for key, item in envelope.items()
                if key != "certificate_digest"})):
            raise ObjectGovernanceError("certificate digest differs")
        if (canonical_bytes(envelope["request"]) != canonical_bytes(selected)
                or envelope["policy_digest"] != "sha256:" + canonical_digest(admitted)
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != selected["proposition_digest"]
                or envelope["evidence_refs"] != [selected["evidence_ref"]]):
            raise ObjectGovernanceError("certificate differs from external selection")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(value) is not str for value in payloads.values())):
            raise ObjectGovernanceError("certificate evidence map differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        current = strict_json_loads(rebuilt.decode("utf-8"))["result"]
        carried = _record(envelope["result"], set(current), "certificate result")
        if (type(carried["status"]) is not str
                or carried["status"] not in {"PASS", "FAIL", "UNKNOWN"}
                or any(canonical_bytes(carried[key]) != canonical_bytes(current[key])
                       for key in current if key not in {"status", "evaluation"})):
            raise ObjectGovernanceError("certificate result invariant differs")
        evaluation = _record(carried["evaluation"], set(current["evaluation"]),
                             "certificate evaluation")
        stable_evaluation = (
            "binding_digest", "evidence_refs", "mechanism_digest",
            "mechanism_id", "observed_evidence_bytes", "trust_roots")
        if (evaluation["outcome"] != carried["status"]
                or any(canonical_bytes(evaluation[key]) != canonical_bytes(current["evaluation"][key])
                       for key in stable_evaluation)):
            raise ObjectGovernanceError("certificate evaluation invariant differs")
        if (type(evaluation["details"]) is not str
                or type(evaluation["observations"]) is not dict):
            raise ObjectGovernanceError("certificate evaluation shape differs")
        if carried["status"] == "PASS":
            retained = _evidence(store.resolve(selected["evidence_ref"]))
            status_payload = retained["status"]["payload"]
            expected_observations = {
                "approvals": len(retained["decisions"]),
                "quorum": admitted["quorum"],
                "status_as_of": _time(status_payload["as_of"]),
                "policy_revision": admitted["revision"],
            }
            # This checks decidable retained-record bindings, not signatures.
            # Authentication still comes only from the complete native replay.
            if (canonical_bytes(evaluation["observations"])
                    != canonical_bytes(expected_observations)
                    or expected_observations["approvals"] < admitted["quorum"]
                    or evaluation["details"] != (
                        'configured signed quorum and fresh status admit selected ' + selected["object_kind"])):
                raise ObjectGovernanceError("certificate observation invariant differs")
        elif evaluation["observations"] and not (
                carried["status"] == "UNKNOWN"
                and evaluation["observations"] == {
                    "checking_dependency": "SIGNATURE_BACKEND_UNAVAILABLE"}):
            raise ObjectGovernanceError("certificate negative observation differs")
        if rebuilt != certificate_bytes:
            if (current["status"] == "UNKNOWN"
                    and current["evaluation"]["observations"].get(
                        "checking_dependency") == "SIGNATURE_BACKEND_UNAVAILABLE"):
                return {**current, "replay_status": "UNAVAILABLE"}
            raise ObjectGovernanceError("certificate result does not reproduce")
        return envelope["result"]
    except (UnicodeError, ValueError, TypeError, KeyError,
            OverflowError, RecursionError) as exc:
        if isinstance(exc, ObjectGovernanceError):
            raise
        raise ObjectGovernanceError("selected governance certificate cannot replay") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "PROPOSITION_DIGEST", "SCOPE",
    "REQUEST_VERSION", "POLICY_VERSION", "EVIDENCE_VERSION", "DECISION_VERSION",
    "STATUS_VERSION", "ENVELOPE_VERSION", "CERTIFICATE_VERSION",
    "ObjectGovernanceError", "GovernanceDescriptor", "KindGovernanceDescriptor",
    "coordinate", "registration", "proposition_digest", "mechanism_digest",
    "governance_policy", "governance_request", "signing_bytes",
    "build_governance_certificate", "recheck_governance_certificate",
]
