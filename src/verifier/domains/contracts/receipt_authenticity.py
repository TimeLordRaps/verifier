"""Current RECEIPT-9.2 selected issuer-key signature and chain prerequisite.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Ed25519 is the Edwards-curve digital signature
algorithm with a 255-bit field. Times are integer Coordinated Universal Time
(UTC) Unix seconds; byte limits count octets. A configured key is not a person,
governance authority, trusted clock, or permission to publish retained bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core import signature_keys
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.receipt import strict_json_loads
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import receipt_chain, retained_selection

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "RECEIPT-9.2"
REQUEST_VERSION = "verifier-current-receipt-authenticity-request-1"
POLICY_VERSION = "verifier-current-receipt-authenticity-policy-1"
EVIDENCE_VERSION = "verifier-current-receipt-authenticity-evidence-1"
CERTIFICATE_VERSION = "verifier-current-receipt-authenticity-certificate-1"
ATTESTATION_VERSION = "verifier-current-receipt-issuer-attestation-1"
MESSAGE_VERSION = "verifier-current-receipt-issuer-message-1"
MECHANISM_ID = "verifier.current-receipt.selected-issuer-signature.1"
SCOPE = "selected_issuer_key_and_retained_receipt_chain"
_PREFIX = b"verifier-current-receipt-issuer-attestation-1\x00"
_HEX32 = re.compile(r"[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{128}\Z")
_MAX_EVIDENCE = 4 * 1024 * 1024
_MAX_CERTIFICATE = 8 * 1024 * 1024
_MAX_TIME = 2**53 - 1


class ReceiptAuthenticityError(ValueError):
    """Malformed external selection or unreproduced canonical certificate."""


class _SignatureBackendUnavailable(Exception):
    """Optional signature implementation cannot execute in this environment."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "RECEIPT", "scope": SCOPE,
        "proposition": "The exact externally selected RECEIPT-9.1 certificate replays PASS, and the externally selected issuer key verifies a domain-separated Ed25519 signature binding that certificate, its request, the selected receipt object, policy, challenge, evaluation time and admitted finite interval.",
        "prerequisites": ["native RECEIPT-9.1 replay under externally selected request and policy", "externally selected admitted issuer public key, challenge and clock value"],
        "exclusions": ["real-world issuer identity, key custody and governance authority", "trusted time, live revocation or one-time challenge consumption", "receipt payload truth, complete history, availability or confidentiality", "whole security tier, object-profile conformance or publication permission"],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


class ReceiptAuthenticityDescriptor:
    """Explicit public-route metadata for one selected issuer-key proposition."""
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               signature_keys, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["specification"] = Path(__file__).parents[2] / "standard" / "CURRENT_RECEIPT_AUTHENTICITY.md"
    return "sha256:" + canonical_digest({
        **{name: hashlib.sha256(path.read_bytes()).hexdigest()
           for name, path in sorted(paths.items())},
        "receipt_chain_mechanism": receipt_chain.mechanism_digest(),
    })


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ReceiptAuthenticityError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ReceiptAuthenticityError)


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_TIME:
        raise ReceiptAuthenticityError("bounded integer UTC Unix seconds required")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 256:
        raise ReceiptAuthenticityError("bounded nonempty issuer key identifier required")
    return value


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes", "issuer_key_id", "issuer_public_key",
        "chain_policy", "max_validity_seconds"}, "policy")
    key_id = _text(selected.pop("issuer_key_id"))
    key = selected.pop("issuer_public_key")
    if type(key) is not str or _HEX32.fullmatch(key) is None:
        raise ReceiptAuthenticityError("canonical 32-byte public key required")
    try:
        signature_keys.admit_ed25519_public_key(bytes.fromhex(key))
    except ValueError as exc:
        raise ReceiptAuthenticityError("issuer public key is inadmissible") from exc
    interval = selected.pop("max_validity_seconds")
    if type(interval) is not int or not 1 <= interval <= 31536000:
        raise ReceiptAuthenticityError("selected validity ceiling must be 1 through 31536000 seconds")
    chain = _record(selected.pop("chain_policy"), {"schema_version", "mechanism_id",
        "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "chain policy")
    admitted_chain = receipt_chain.receipt_chain_policy(
        trust_roots=chain["trust_roots"], max_certificate_bytes=chain["max_certificate_bytes"])
    if canonical_bytes(chain) != canonical_bytes(admitted_chain):
        raise ReceiptAuthenticityError("chain policy differs from installed prerequisite")
    admitted = retained_selection.policy(selected, error_type=ReceiptAuthenticityError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE)
    return {**admitted, "issuer_key_id": key_id, "issuer_public_key": key,
            "chain_policy": admitted_chain, "max_validity_seconds": interval}


def receipt_authenticity_policy(*, issuer_key_id: str, issuer_public_key: str,
        chain_policy: dict[str, Any], trust_roots: list[str],
        max_validity_seconds: int, max_certificate_bytes: int = _MAX_CERTIFICATE) -> dict[str, Any]:
    """Capture external key admission; this helper grants no identity or authority."""
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "issuer_key_id": issuer_key_id,
        "issuer_public_key": issuer_public_key, "chain_policy": chain_policy,
        "max_validity_seconds": max_validity_seconds})


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "receipt_object_id", "receipt_object_digest", "chain_request",
        "chain_certificate_digest", "challenge", "evaluation_time", "evidence_ref",
        "policy_digest", "max_evidence_bytes"}, "request")
    if (any(type(selected[key]) is not str for key in ("schema_version", "semantic_version", "coordinate"))
            or selected["schema_version"] != REQUEST_VERSION or selected["semantic_version"] != SEMANTIC_VERSION
            or selected["coordinate"] != COORDINATE or _digest(selected["proposition_digest"]) != PROPOSITION_DIGEST):
        raise ReceiptAuthenticityError("receipt authenticity objective differs")
    child = _record(selected["chain_request"], {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "receipt_object_id", "receipt_object_digest", "domain", "genesis_digest",
        "first_sequence", "tip_digest", "evidence_ref", "policy_digest", "max_entries", "max_evidence_bytes"}, "chain request")
    keys = ("receipt_object_id", "receipt_object_digest", "domain", "genesis_digest",
            "first_sequence", "tip_digest", "evidence_ref", "max_entries", "max_evidence_bytes")
    admitted_child = receipt_chain.receipt_chain_request(
        **{key: child[key] for key in keys}, policy=policy["chain_policy"])
    if canonical_bytes(child) != canonical_bytes(admitted_child):
        raise ReceiptAuthenticityError("selected chain request differs from prerequisite")
    if (type(selected["receipt_object_id"]) is not str
            or selected["receipt_object_id"] != child["receipt_object_id"]
            or _digest(selected["receipt_object_digest"]) != child["receipt_object_digest"]):
        raise ReceiptAuthenticityError("selected receipt differs from chain subject")
    for key in ("chain_certificate_digest", "evidence_ref", "policy_digest"):
        _digest(selected[key])
    if selected["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ReceiptAuthenticityError("request differs from selected policy")
    if type(selected["challenge"]) is not str or _HEX32.fullmatch(selected["challenge"]) is None:
        raise ReceiptAuthenticityError("externally selected 32-byte challenge required")
    _time(selected["evaluation_time"])
    if type(selected["max_evidence_bytes"]) is not int or not 1 <= selected["max_evidence_bytes"] <= _MAX_EVIDENCE:
        raise ReceiptAuthenticityError("selected evidence byte bound is unsupported")
    selected["chain_request"] = admitted_child
    return selected


def receipt_authenticity_request(*, chain_request: dict[str, Any],
        chain_certificate_digest: str, challenge: str, evaluation_time: int,
        evidence_ref: str, policy: dict[str, Any],
        max_evidence_bytes: int = _MAX_EVIDENCE) -> dict[str, Any]:
    admitted = _policy(policy)
    if type(chain_request) is not dict:
        raise ReceiptAuthenticityError("plain prerequisite request required")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "receipt_object_id": chain_request.get("receipt_object_id"),
        "receipt_object_digest": chain_request.get("receipt_object_digest"),
        "chain_request": chain_request, "chain_certificate_digest": chain_certificate_digest,
        "challenge": challenge, "evaluation_time": evaluation_time, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "max_evidence_bytes": max_evidence_bytes}, admitted)


def receipt_authenticity_payload(request: dict[str, Any], *, policy: dict[str, Any],
        issued_at: int, expires_at: int) -> dict[str, Any]:
    """Create signable selected intent; the signature-containing evidence is not self-hashed."""
    admitted = _policy(policy); selected = _request(request, admitted)
    return {"schema_version": MESSAGE_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "issuer_key_id": admitted["issuer_key_id"],
        **{key: selected[key] for key in ("receipt_object_id", "receipt_object_digest",
            "chain_certificate_digest", "challenge", "evaluation_time", "policy_digest")},
        "chain_request_digest": "sha256:" + canonical_digest(selected["chain_request"]),
        "issued_at": _time(issued_at), "expires_at": _time(expires_at)}


def receipt_authenticity_signing_bytes(payload: dict[str, Any]) -> bytes:
    """Domain-separate canonical selected intent; signing requires a separately held key."""
    selected = _record(payload, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "issuer_key_id", "receipt_object_id", "receipt_object_digest",
        "chain_certificate_digest", "challenge", "evaluation_time", "policy_digest",
        "chain_request_digest", "issued_at", "expires_at"}, "signed payload")
    encoded = canonical_bytes(selected)
    if len(encoded) > 8192:
        raise ReceiptAuthenticityError("signed payload exceeds 8192 bytes")
    return _PREFIX + encoded


def _verify_signature(public_key: str, signature: str, message: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise _SignatureBackendUnavailable from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(signature), message)
    except UnsupportedAlgorithm as exc:
        raise _SignatureBackendUnavailable from exc
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refuted("selected issuer-key signature does not verify") from exc


def _positive_observations(request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    return {"receipt_chain_status": "PASS", "chain_certificate_digest": request["chain_certificate_digest"],
        "issuer_key_sha256": "sha256:" + hashlib.sha256(bytes.fromhex(policy["issuer_public_key"])).hexdigest(),
        "evaluation_time": request["evaluation_time"]}


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "chain_certificate", "attestation"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        child_status = "UNKNOWN"
        if value["chain_certificate"] is not None:
            if type(value["chain_certificate"]) is not str:
                raise Refuted("retained chain certificate must be text or unavailable")
            child = value["chain_certificate"].encode("utf-8")
            if len(child) > policy["chain_policy"]["max_certificate_bytes"]:
                raise Unavailable("retained chain certificate byte bound exhausted")
            if "sha256:" + hashlib.sha256(child).hexdigest() != request["chain_certificate_digest"]:
                raise Refuted("retained chain certificate differs from external selection")
            child_status = receipt_chain.recheck_receipt_chain_certificate(child,
                expected_request=request["chain_request"], policy=policy["chain_policy"])["status"]
            if child_status == "FAIL":
                raise Refuted("selected receipt-chain prerequisite refuted")
        if value["attestation"] is None:
            raise Unavailable("retained issuer attestation absent")
        attestation = _record(value["attestation"], {"schema_version", "key_id", "payload", "signature"}, "attestation")
        if (attestation["schema_version"] != ATTESTATION_VERSION or attestation["key_id"] != policy["issuer_key_id"]
                or type(attestation["signature"]) is not str or _HEX64.fullmatch(attestation["signature"]) is None
                or type(attestation["payload"]) is not dict):
            raise Refuted("issuer attestation key, version or signature encoding differs")
        payload = attestation["payload"]
        expected = receipt_authenticity_payload(request, policy=policy,
            issued_at=payload.get("issued_at"), expires_at=payload.get("expires_at"))
        if canonical_bytes(payload) != canonical_bytes(expected):
            raise Refuted("signed intent differs from external selection")
        start, end, now = expected["issued_at"], expected["expires_at"], request["evaluation_time"]
        if not start <= now < end or not 1 <= end - start <= policy["max_validity_seconds"]:
            raise Refuted("selected clock is outside admitted signed interval")
        backend_missing = False
        try:
            _verify_signature(policy["issuer_public_key"], attestation["signature"], receipt_authenticity_signing_bytes(expected))
        except _SignatureBackendUnavailable:
            backend_missing = True
        if child_status != "PASS":
            raise Unavailable("selected receipt-chain prerequisite unavailable")
        if backend_missing:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "signature backend unavailable",
                {"checking_dependency": "SIGNATURE_BACKEND_UNAVAILABLE"})
        return MechanismDecision(MechanismOutcome.PASS, "selected issuer signature and receipt-chain prerequisite verified",
            _positive_observations(request, policy))
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _Mechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["receipt_object_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "selected issuer proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained issuer evidence bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    binding = BoundProposition(subject_id=request["receipt_object_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store); session.register(_Mechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "RECEIPT", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "security_tier_conformance": "NOT_ESTABLISHED",
        "real_world_issuer_identity": "NOT_ESTABLISHED", "governance_authority": "NOT_ESTABLISHED",
        "trusted_time": "NOT_ESTABLISHED", "live_revocation": "NOT_ESTABLISHED",
        "challenge_consumption": "NOT_ESTABLISHED", "public_disclosure_authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64([request["evidence_ref"]] if request["evidence_ref"] in store else []), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ReceiptAuthenticityError("certificate byte bound exhausted")
    return encoded


def build_receipt_authenticity_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    admitted = _policy(policy); selected = _request(request, admitted); store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _MAX_EVIDENCE:
            raise ReceiptAuthenticityError("bounded immutable evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ReceiptAuthenticityError("evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_receipt_authenticity_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    admitted = _policy(policy); selected = _request(expected_request, admitted)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ReceiptAuthenticityError("bounded immutable certificate required")
    try:
        envelope = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
             "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(envelope) != certificate_bytes or envelope["schema_version"] != CERTIFICATE_VERSION
                or envelope["digest"] != "sha256:" + canonical_digest({k: v for k, v in envelope.items() if k != "digest"})
                or canonical_bytes(envelope["request"]) != canonical_bytes(selected)
                or envelope["policy_digest"] != selected["policy_digest"]
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_refs"] != [selected["evidence_ref"]]):
            raise ReceiptAuthenticityError("certificate differs from external selection")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]}
                or any(type(value) is not str for value in payloads.values())):
            raise ReceiptAuthenticityError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        current = strict_json_loads(rebuilt.decode("utf-8"))["result"]
        if rebuilt == certificate_bytes:
            return current
        if current["status"] == "UNKNOWN" and current["evaluation"]["observations"] == {"checking_dependency": "SIGNATURE_BACKEND_UNAVAILABLE"}:
            carried = _record(envelope["result"], set(current), "carried result")
            if (type(carried["status"]) is not str or carried["status"] not in {"PASS", "FAIL", "UNKNOWN"}
                    or any(canonical_bytes(carried[k]) != canonical_bytes(current[k]) for k in current if k not in {"status", "evaluation"})):
                raise ReceiptAuthenticityError("carried result invariant differs")
            evaluation = _record(carried["evaluation"], set(current["evaluation"]), "carried evaluation")
            dynamic = {"outcome", "details", "observations"}
            if (evaluation["outcome"] != carried["status"] or type(evaluation["details"]) is not str
                    or any(canonical_bytes(evaluation[k]) != canonical_bytes(current["evaluation"][k]) for k in evaluation if k not in dynamic)):
                raise ReceiptAuthenticityError("carried evaluation binding differs")
            if carried["status"] == "PASS":
                if (evaluation["details"] != "selected issuer signature and receipt-chain prerequisite verified"
                        or canonical_bytes(evaluation["observations"]) != canonical_bytes(_positive_observations(selected, admitted))):
                    raise ReceiptAuthenticityError("carried positive observation differs")
            elif evaluation["observations"] not in ({}, {"checking_dependency": "SIGNATURE_BACKEND_UNAVAILABLE"}):
                raise ReceiptAuthenticityError("carried negative observation differs")
            return {**current, "replay_status": "UNAVAILABLE"}
        raise ReceiptAuthenticityError("certificate result does not reproduce")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ReceiptAuthenticityError):
            raise
        raise ReceiptAuthenticityError("issuer certificate cannot replay") from exc
