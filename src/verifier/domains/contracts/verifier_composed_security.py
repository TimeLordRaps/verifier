"""Selected ten-tier VERIFIER-6.1: exact signed retained subject association.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII). Ed25519 is the
Edwards-curve digital signature algorithm with a 255-bit field. Byte limits
count octets; generation and checking
counts are dimensionless. This direct-module experimental contract composes
native nine-tier VERIFIER-9.1 association and RECEIPT-9.2 issuer-key replay
without renaming either child. A finite PASS is not whole security admission,
authority, execution, key custody, human acceptance or production admission.
"""
from __future__ import annotations

from asyncio import CancelledError
import base64
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import (
    receipt_authenticity, receipt_chain, retained_selection, subject_security,
)

SEMANTIC_VERSION = "verifier-current-ten-tier-object-obligations-1"
COORDINATE = "VERIFIER-6.1"
REQUEST_VERSION = "verifier-ten-tier-verifier-composed-security-request-1"
POLICY_VERSION = "verifier-ten-tier-verifier-composed-security-policy-1"
EVIDENCE_VERSION = "verifier-ten-tier-verifier-composed-security-evidence-1"
CERTIFICATE_VERSION = "verifier-ten-tier-verifier-composed-security-certificate-1"
CONTEXT_VERSION = "verifier-ten-tier-verifier-security-context-1"
SELECTOR_VERSION = "verifier-ten-tier-verifier-security-selection-1"
MECHANISM_ID = "verifier.ten-tier.verifier.selected-signed-association.1"
SCOPE = "selected_exact_signed_verifier_association"
_MAX_SELECTION_BYTES = 1024 * 1024
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_VALUES = 50000
_MAX_ITEMS = 4096
_MAX_DEPTH = 48
_MAX_GENERATION = 2**53 - 1
_CONTEXT_FIELDS = {
    "schema_version", "subject_id", "object_digest", "artifact_digests",
    "instruction_digest", "context_revision_digest", "generation",
    "operation_id", "session_id", "process_id", "authority_policy_digest",
}
_ENVELOPE_FIELDS = {
    "schema_version", "request", "policy_digest", "mechanism_digest",
    "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
}
_EXCLUDED = (
    "whole_security_admission", "object_profile_conformance", "authority",
    "key_custody", "trusted_time", "live_revocation", "challenge_consumption",
    "actual_execution", "human_acceptance", "production_admission",
    "public_disclosure_authority", "context_consumption",
)
_PASS_DETAILS = "both exact native certificates reproduce the selected signed association"


class VerifierComposedSecurityError(ValueError):
    """Malformed external selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-ten-tier-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "VERIFIER", "scope": SCOPE,
        "proposition": (
            "The selected native VERIFIER-9.1 association and RECEIPT-9.2 "
            "issuer-key certificates both replay PASS, bind one identical "
            "externally selected chain request, chain policy and exact retained "
            "chain certificate, and associate the exact VERIFIER record with "
            "the canonical externally selected artifact, instruction, context "
            "revision, generation, operation, session, process and authority-policy binding."
        ),
        "prerequisites": [
            "independently selected exact requests, policies, certificate digests and context",
            "both retained native certificates and their identical retained chain bytes",
        ],
        "exclusions": list(_EXCLUDED),
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


class VerifierComposedSecurityDescriptor:
    """Metadata for this distinct selected semantic family and fixed coordinate."""
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _capture(value: Any) -> Any:
    """Bound and copy exact plain values before canonicalization or native readers."""
    state = {"values": 0, "text_bytes": 0}

    def visit(item: Any, depth: int) -> Any:
        state["values"] += 1
        if state["values"] > _MAX_VALUES or depth > _MAX_DEPTH:
            raise VerifierComposedSecurityError("selection structural bound exhausted")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > 4096:
                raise VerifierComposedSecurityError("selection integer bound exhausted")
            return item
        if kind is str:
            if len(item) > _MAX_SELECTION_BYTES - state["text_bytes"]:
                raise VerifierComposedSecurityError("selection text bound exhausted")
            state["text_bytes"] += len(item.encode("utf-8"))
            if state["text_bytes"] > _MAX_SELECTION_BYTES:
                raise VerifierComposedSecurityError("selection text bound exhausted")
            return item
        if kind is list:
            if len(item) > _MAX_ITEMS:
                raise VerifierComposedSecurityError("selection item bound exhausted")
            return [visit(child, depth + 1) for child in item]
        if kind is dict:
            if len(item) > _MAX_ITEMS or any(type(key) is not str for key in item):
                raise VerifierComposedSecurityError("plain bounded selection keys required")
            return {visit(key, depth + 1): visit(child, depth + 1)
                    for key, child in item.items()}
        raise VerifierComposedSecurityError("exact plain selection values required")

    captured = visit(value, 0)
    if len(canonical_bytes(captured)) > _MAX_SELECTION_BYTES:
        raise VerifierComposedSecurityError("selection byte bound exhausted")
    return captured


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, VerifierComposedSecurityError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, VerifierComposedSecurityError)


def _label(value: Any) -> str:
    if (type(value) is not str or len(value) > 256 or not value.strip()
            or len(value.encode("utf-8")) > 256 or any(ord(c) < 32 for c in value)):
        raise VerifierComposedSecurityError("bounded nonempty identifier required")
    return value


def context_binding(value: Any) -> dict[str, Any]:
    """Capture externally supplied context; this helper authenticates no producer."""
    selected = _record(_capture(value), _CONTEXT_FIELDS, "context binding")
    if selected["schema_version"] != CONTEXT_VERSION:
        raise VerifierComposedSecurityError("context binding version differs")
    for field in ("subject_id", "operation_id", "session_id", "process_id"):
        _label(selected[field])
    for field in ("object_digest", "instruction_digest", "context_revision_digest",
                  "authority_policy_digest"):
        _digest(selected[field])
    generation = selected["generation"]
    if type(generation) is not int or not 0 <= generation <= _MAX_GENERATION:
        raise VerifierComposedSecurityError("bounded plain integer generation required")
    artifacts = selected["artifact_digests"]
    if type(artifacts) is not list or not 1 <= len(artifacts) <= 256:
        raise VerifierComposedSecurityError("one to 256 artifact commitments required")
    for item in artifacts:
        _digest(item)
    if artifacts != sorted(set(artifacts)):
        raise VerifierComposedSecurityError("sorted unique artifact commitments required")
    return selected


def context_digest(value: Any) -> str:
    return "sha256:" + canonical_digest(context_binding(value))


def mechanism_digest() -> str:
    """Pin this module/specification and every composed native mechanism dependency."""
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["specification"] = (
        Path(__file__).parents[2] / "standard" / "CURRENT_VERIFIER_COMPOSED_SECURITY.md"
    )
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TEN_TIER_PROGRESSION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        **{name: hashlib.sha256(path.read_bytes()).hexdigest()
           for name, path in sorted(paths.items())},
        "association_mechanism": subject_security.mechanism_digest("VERIFIER"),
        "authenticity_mechanism": receipt_authenticity.mechanism_digest(),
        "chain_mechanism": receipt_chain.mechanism_digest(),
    })


def _policy(value: Any) -> dict[str, Any]:
    """Capture the carried external pin; installed-source admission is delayed."""
    selected = _record(_capture(value), {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "association_policy", "authenticity_policy",
    }, "policy")
    if (type(selected["association_policy"]) is not dict
            or type(selected["authenticity_policy"]) is not dict):
        raise VerifierComposedSecurityError("exact native child policy records required")
    _policy_fields(selected, POLICY_VERSION, MECHANISM_ID, _MAX_CERTIFICATE_BYTES)
    return selected


def _integer(value: Any, lower: int, upper: int) -> None:
    if type(value) is not int or not lower <= value <= upper:
        raise VerifierComposedSecurityError("bounded plain integer required")


def _hex(value: Any, digits: int) -> None:
    if (type(value) is not str or len(value) != digits
            or any(c not in "0123456789abcdef" for c in value)):
        raise VerifierComposedSecurityError("canonical bounded hexadecimal required")


def _policy_fields(value: dict[str, Any], version: str, mechanism_id: str,
                   ceiling: int) -> None:
    """Source-free validation of captured common policy fields."""
    if value["schema_version"] != version or value["mechanism_id"] != mechanism_id:
        raise VerifierComposedSecurityError("selected policy version or mechanism differs")
    _digest(value["mechanism_digest"])
    roots = value["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise VerifierComposedSecurityError("bounded trust-root labels required")
    for root in roots:
        _label(root)
    if roots != sorted(set(roots)):
        raise VerifierComposedSecurityError("sorted unique trust-root labels required")
    _integer(value["max_certificate_bytes"], 1, ceiling)


def verifier_composed_security_policy(*, association_policy: dict[str, Any],
        authenticity_policy: dict[str, Any], trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
        "association_policy": association_policy,
        "authenticity_policy": authenticity_policy,
    })


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    selected = _record(_capture(value), {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "context_binding",
        "association_request", "authenticity_request",
        "association_certificate_digest", "authenticity_certificate_digest",
        "evidence_ref", "policy_digest", "max_evidence_bytes", "cancelled",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "VERIFIER"),
    ):
        if type(selected[field]) is not str or selected[field] != expected:
            raise VerifierComposedSecurityError("selected composed-security objective differs")
    _label(selected["subject_id"])
    for field in ("object_digest", "association_certificate_digest",
                  "authenticity_certificate_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    if selected["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise VerifierComposedSecurityError("request differs from selected outer policy")
    selected["context_binding"] = context_binding(selected["context_binding"])
    if (type(selected["association_request"]) is not dict
            or type(selected["authenticity_request"]) is not dict):
        raise VerifierComposedSecurityError("exact selected native request records required")
    if type(selected["cancelled"]) is not bool:
        raise VerifierComposedSecurityError("plain selected cancellation flag required")
    limit = selected["max_evidence_bytes"]
    if type(limit) is not int or not 1 <= limit <= _MAX_EVIDENCE_BYTES:
        raise VerifierComposedSecurityError("selected evidence byte bound unsupported")
    return selected


def verifier_composed_security_request(*, subject_id: str, object_digest: str,
        context_binding: dict[str, Any], association_request: dict[str, Any],
        authenticity_request: dict[str, Any], association_certificate_digest: str,
        authenticity_certificate_digest: str, evidence_ref: str, policy: dict[str, Any],
        cancelled: bool = False,
        max_evidence_bytes: int = _MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    admitted = _policy(policy)
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "VERIFIER", "subject_id": subject_id,
        "object_digest": object_digest, "context_binding": context_binding,
        "association_request": association_request, "authenticity_request": authenticity_request,
        "association_certificate_digest": association_certificate_digest,
        "authenticity_certificate_digest": authenticity_certificate_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "cancelled": cancelled, "max_evidence_bytes": max_evidence_bytes,
    }, admitted)


def _cheap_child(name: str, child: dict[str, Any], policy: dict[str, Any]) -> None:
    """Closed native syntax and binding checks, without installed-source readers."""
    association = name == "association"
    module = subject_security if association else receipt_authenticity
    policy_fields = {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "chain_policy",
    } | ({"object_kind"} if association else {
        "issuer_key_id", "issuer_public_key", "max_validity_seconds",
    })
    _record(policy, policy_fields, "native policy")
    _policy_fields(policy, module.POLICY_VERSION, module.MECHANISM_ID, 8 * 1024 * 1024)
    if association:
        if policy["object_kind"] != "VERIFIER":
            raise VerifierComposedSecurityError("selected native policy object kind differs")
    else:
        _label(policy["issuer_key_id"])
        _hex(policy["issuer_public_key"], 64)
        # Native key screening uses bounded standard-library arithmetic, not
        # the optional signature backend or installed mechanism source readers.
        receipt_authenticity.signature_keys.admit_ed25519_public_key(
            bytes.fromhex(policy["issuer_public_key"]))
        _integer(policy["max_validity_seconds"], 1, 31536000)
    cp = _record(policy["chain_policy"], {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes",
    }, "native chain policy")
    _policy_fields(cp, receipt_chain.POLICY_VERSION, receipt_chain.MECHANISM_ID, 2 * 1024 * 1024)
    child_fields = {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "chain_request", "chain_certificate_digest", "evidence_ref", "policy_digest",
        "max_evidence_bytes",
    } | ({"object_kind", "subject_id", "object_digest", "context_digest", "chain_sequence"}
         if association else {"receipt_object_id", "receipt_object_digest", "challenge", "evaluation_time"})
    _record(child, child_fields, "native request")
    proposition = (subject_security.SubjectSecurityDescriptor("VERIFIER").PROPOSITION_DIGEST
                   if association else receipt_authenticity.PROPOSITION_DIGEST)
    for field, expected in (
        ("schema_version", module.REQUEST_VERSION),
        ("semantic_version", "verifier-current-object-obligations-1"),
        ("coordinate", "VERIFIER-9.1" if association else "RECEIPT-9.2"),
        ("proposition_digest", proposition),
    ):
        if child[field] != expected:
            raise VerifierComposedSecurityError("selected native objective differs")
    for field in ("chain_certificate_digest", "evidence_ref", "policy_digest"):
        _digest(child[field])
    if child["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise VerifierComposedSecurityError("selected native request policy differs")
    _integer(child["max_evidence_bytes"], 1, 4 * 1024 * 1024)
    cr = _record(child["chain_request"], {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "receipt_object_id", "receipt_object_digest", "domain", "genesis_digest",
        "first_sequence", "tip_digest", "evidence_ref", "policy_digest",
        "max_entries", "max_evidence_bytes",
    }, "native chain request")
    for field, expected in (
        ("schema_version", receipt_chain.REQUEST_VERSION),
        ("semantic_version", "verifier-current-object-obligations-1"),
        ("coordinate", "RECEIPT-9.1"),
        ("proposition_digest", receipt_chain.PROPOSITION_DIGEST),
        ("policy_digest", "sha256:" + canonical_digest(cp)),
    ):
        if cr[field] != expected:
            raise VerifierComposedSecurityError("selected native chain objective or policy differs")
    _label(cr["receipt_object_id"])
    _label(cr["domain"])
    for field in ("receipt_object_digest", "genesis_digest", "tip_digest",
                  "evidence_ref", "policy_digest"):
        _digest(cr[field])
    _integer(cr["first_sequence"], 0, 2**63 - 1)
    _integer(cr["max_entries"], 1, 64)
    _integer(cr["max_evidence_bytes"], 1, 1024 * 1024)
    if association:
        if child["object_kind"] != "VERIFIER":
            raise VerifierComposedSecurityError("selected native object kind differs")
        _label(child["subject_id"])
        _digest(child["object_digest"])
        _digest(child["context_digest"])
        _integer(child["chain_sequence"], 0, 2**63 - 1)
        if not cr["first_sequence"] <= child["chain_sequence"] < cr["first_sequence"] + cr["max_entries"]:
            raise VerifierComposedSecurityError("selected native association sequence differs")
    else:
        if (child["receipt_object_id"] != cr["receipt_object_id"]
                or child["receipt_object_digest"] != cr["receipt_object_digest"]):
            raise VerifierComposedSecurityError("selected native receipt subject differs")
        _hex(child["challenge"], 64)
        _integer(child["evaluation_time"], 0, _MAX_GENERATION)


def _selection_failures(request: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    """Known closed-field contradictions precede absent evidence and source I/O."""
    failures = []
    association, authenticity = request["association_request"], request["authenticity_request"]
    ap, ip = policy["association_policy"], policy["authenticity_policy"]
    binding = request["context_binding"]
    if (binding["subject_id"] != request["subject_id"]
            or binding["object_digest"] != request["object_digest"]):
        failures.append("selected context names another VERIFIER")
    for name in ("chain_request", "chain_certificate_digest"):
        if canonical_bytes(association.get(name)) != canonical_bytes(authenticity.get(name)):
            failures.append("selected native " + name + " differs")
    if canonical_bytes(ap.get("chain_policy")) != canonical_bytes(ip.get("chain_policy")):
        failures.append("selected native chain_policy differs")
    if (association.get("object_kind") != "VERIFIER"
            or association.get("subject_id") != request["subject_id"]
            or association.get("object_digest") != request["object_digest"]
            or association.get("context_digest") != context_digest(binding)):
        failures.append("selected association subject or context differs")
    for name, child, child_policy in (
        ("association", association, ap),
        ("authenticity", authenticity, ip),
    ):
        try:
            _cheap_child(name, child, child_policy)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
            failures.append("selected " + name + " native selection is refused")
    return failures


def _json(data: bytes) -> Any:
    """Bound syntax before recursive decoding; no unavailable tail is certified."""
    depth, containers, digits = 0, 0, 0
    quoted = escaped = False
    for octet in data:
        if quoted:
            if escaped:
                escaped = False
            elif octet == 92:
                escaped = True
            elif octet == 34:
                quoted = False
            continue
        if octet == 34:
            quoted, digits = True, 0
        elif octet in (91, 123):
            depth += 1
            containers += 1
            digits = 0
            if depth > _MAX_DEPTH or containers > _MAX_VALUES:
                raise Unavailable("retained decoder structural capacity exhausted")
        elif octet in (93, 125):
            depth -= 1
            digits = 0
        elif 48 <= octet <= 57:
            digits += 1
            if digits > 1234:
                raise Unavailable("retained decoder integer capacity exhausted")
        else:
            digits = 0
    try:
        value = strict_json_loads(data.decode("utf-8"))
        if canonical_bytes(value) != data:
            raise Refuted("retained bytes are noncanonical")
        return value
    except (RecursionError, OverflowError) as exc:
        raise Unavailable("retained decoder capacity unavailable") from exc


def _b64(value: Any, limit: int) -> bytes:
    if type(value) is not str:
        raise Refuted("retained certificate must be canonical base64 or null")
    if len(value) > 4 * ((limit + 2) // 3):
        raise Unavailable("retained decoded byte ceiling exhausted")
    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted("retained base64 is noncanonical")
    if len(decoded) > limit:
        raise Unavailable("retained decoded byte ceiling exhausted")
    return decoded


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _child_evidence(raw: bytes, request: dict[str, Any], policy: dict[str, Any],
                    version: str) -> Any:
    envelope = _record(_json(raw), _ENVELOPE_FIELDS, "native certificate")
    if (envelope["schema_version"] != version
            or envelope["digest"] != "sha256:" + canonical_digest({
                key: value for key, value in envelope.items() if key != "digest"})
            or canonical_bytes(envelope["request"]) != canonical_bytes(request)
            or envelope["policy_digest"] != request["policy_digest"]
            or envelope["mechanism_digest"] != policy["mechanism_digest"]
            or envelope["proposition_digest"] != request["proposition_digest"]
            or envelope["evidence_refs"] != [request["evidence_ref"]]):
        raise Refuted("retained native certificate selection differs")
    payloads = envelope["evidence_payloads"]
    if (type(payloads) is not dict or set(payloads) - {request["evidence_ref"]}
            or len(payloads) > 1):
        raise Refuted("retained native evidence references differ")
    if request["evidence_ref"] not in payloads:
        return None
    evidence = _b64(payloads[request["evidence_ref"]], request["max_evidence_bytes"])
    if _hash(evidence) != request["evidence_ref"]:
        raise Refuted("retained native evidence commitment differs")
    return _json(evidence)


def _association_subject(value: Any, request: dict[str, Any]) -> None:
    record = _record(value, {"object_id", "kind", "payload", "operands"}, "subject")
    if type(record["operands"]) is not dict:
        raise Refuted("subject operands are not a plain map")
    item = NamespaceObject.create(**record)
    if (canonical_bytes(item.to_dict()) != canonical_bytes(record)
            or item.kind.value != "VERIFIER" or item.object_id != request["subject_id"]
            or item.digest != request["object_digest"]):
        raise Refuted("retained VERIFIER subject differs")


def _chain_bytes(value: Any, request: dict[str, Any], policy: dict[str, Any]) -> bytes | None:
    if value is None:
        return None
    if type(value) is not str:
        raise Refuted("native retained chain certificate is not exact text")
    raw = value.encode("utf-8")
    if len(raw) > policy["chain_policy"]["max_certificate_bytes"]:
        raise Unavailable("native retained chain certificate bound exhausted")
    if _hash(raw) != request["chain_certificate_digest"]:
        raise Refuted("native retained chain certificate digest differs")
    return raw


def _association_intent(raw: bytes, request: dict[str, Any],
                        policy: dict[str, Any]) -> None:
    chain_request = request["chain_request"]
    chain = _child_evidence(raw, chain_request, policy["chain_policy"],
                            receipt_chain.CERTIFICATE_VERSION)
    if chain is None:
        return
    chain = _record(chain, {"schema_version", "domain", "receipt_object", "entries"}, "chain evidence")
    if chain["schema_version"] != receipt_chain.EVIDENCE_VERSION:
        raise Refuted("retained chain evidence version differs")
    record = _record(chain["receipt_object"], {"object_id", "kind", "payload", "operands"}, "receipt")
    if type(record["operands"]) is not dict or record["operands"].get("subject") != [request["subject_id"]]:
        raise Refuted("retained chain receipt names another subject")
    entries = chain["entries"]
    offset = request["chain_sequence"] - chain_request["first_sequence"]
    if type(entries) is not list or not 0 <= offset < len(entries):
        raise Refuted("selected association entry is missing")
    entry = _record(entries[offset], {"sequence", "receipt_base64"}, "chain entry")
    if entry["sequence"] != request["chain_sequence"]:
        raise Refuted("retained association sequence differs")
    # Literal closed native wire comparison deliberately performs no producer
    # helper or installed-source read before retained binding refutation.
    expected = {
        "schema_version": subject_security.MESSAGE_VERSION,
        "semantic_version": "verifier-current-object-obligations-1",
        "coordinate": "VERIFIER-9.1",
        "proposition_digest": subject_security.SubjectSecurityDescriptor("VERIFIER").PROPOSITION_DIGEST,
        "object_kind": "VERIFIER", "subject_id": request["subject_id"],
        "object_digest": request["object_digest"],
        "receipt_object_id": chain_request["receipt_object_id"],
        "chain_domain": chain_request["domain"],
        "chain_genesis_digest": chain_request["genesis_digest"],
        "chain_first_sequence": chain_request["first_sequence"],
        "chain_sequence": request["chain_sequence"], "context_digest": request["context_digest"],
        "policy_digest": request["policy_digest"],
    }
    if _b64(entry["receipt_base64"], 256 * 1024) != canonical_bytes(expected):
        raise Refuted("retained typed-subject intent differs")


def _attestation(value: Any, request: dict[str, Any], policy: dict[str, Any]) -> None:
    if value is None:
        return
    row = _record(value, {"schema_version", "key_id", "payload", "signature"}, "attestation")
    signature = row["signature"]
    if (row["schema_version"] != receipt_authenticity.ATTESTATION_VERSION
            or row["key_id"] != policy["issuer_key_id"] or type(signature) is not str
            or len(signature) != 128 or any(c not in "0123456789abcdef" for c in signature)
            or type(row["payload"]) is not dict):
        raise Refuted("retained issuer attestation fields differ")
    payload = row["payload"]
    start, end = payload.get("issued_at"), payload.get("expires_at")
    _integer(start, 0, _MAX_GENERATION)
    _integer(end, 0, _MAX_GENERATION)
    expected = {
        "schema_version": receipt_authenticity.MESSAGE_VERSION,
        "semantic_version": "verifier-current-object-obligations-1",
        "coordinate": "RECEIPT-9.2",
        "proposition_digest": receipt_authenticity.PROPOSITION_DIGEST,
        "issuer_key_id": policy["issuer_key_id"],
        "receipt_object_id": request["receipt_object_id"],
        "receipt_object_digest": request["receipt_object_digest"],
        "chain_certificate_digest": request["chain_certificate_digest"],
        "chain_request_digest": "sha256:" + canonical_digest(request["chain_request"]),
        "challenge": request["challenge"], "evaluation_time": request["evaluation_time"],
        "policy_digest": request["policy_digest"], "issued_at": start, "expires_at": end,
    }
    if canonical_bytes(payload) != canonical_bytes(expected):
        raise Refuted("retained issuer intent differs")
    if (not start <= request["evaluation_time"] < end
            or not 1 <= end - start <= policy["max_validity_seconds"]):
        raise Refuted("retained issuer interval contradicts selection")


def _observations(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "context_digest": context_digest(request["context_binding"]),
        "association_certificate_digest": request["association_certificate_digest"],
        "authenticity_certificate_digest": request["authenticity_certificate_digest"],
        "chain_certificate_digest": request["association_request"].get("chain_certificate_digest"),
    }


def _native_replay(name: str, raw: bytes, request: dict[str, Any],
                   policy: dict[str, Any]) -> tuple[str, bool]:
    recheck = (subject_security.recheck_subject_security_certificate if name == "association"
               else receipt_authenticity.recheck_receipt_authenticity_certificate)
    try:
        result = recheck(raw, expected_request=request, policy=policy)
        if result.get("status") not in {"PASS", "FAIL", "UNKNOWN"}:
            return "FAIL", False
        return result["status"], result.get("replay_status") == "UNAVAILABLE"
    except (OSError, ImportError, MemoryError, CancelledError, Unavailable, RecursionError, OverflowError):
        return "UNKNOWN", True
    except (ValueError, TypeError, KeyError, UnicodeError):
        return "FAIL", False
    except Exception:
        # Fence unsupported native support crashes per child: the session's
        # whole-mechanism crash fallback must not erase a prior fresh FAIL.
        return "UNKNOWN", True


def _evaluate(data: bytes | None, request: dict[str, Any],
              policy: dict[str, Any]) -> MechanismDecision:
    failures = _selection_failures(request, policy)
    if failures:
        return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(set(failures))))
    if data is None:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "required candidate evidence absent")
    if len(data) > request["max_evidence_bytes"]:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "selected candidate byte bound exhausted")
    certificates, chains = {}, {}
    unavailable = False
    try:
        value = _record(_json(data), {
            "schema_version", "context_binding", "association_certificate",
            "authenticity_certificate",
        }, "composed evidence")
        if value["schema_version"] != EVIDENCE_VERSION:
            raise Refuted("retained composed evidence version differs")
        if canonical_bytes(context_binding(value["context_binding"])) != canonical_bytes(request["context_binding"]):
            failures.append("retained context binding differs")
        for name, module in (("association", subject_security), ("authenticity", receipt_authenticity)):
            child_request, child_policy = request[name + "_request"], policy[name + "_policy"]
            if value[name + "_certificate"] is None:
                unavailable = True
                continue
            try:
                raw = _b64(value[name + "_certificate"], child_policy["max_certificate_bytes"])
                if _hash(raw) != request[name + "_certificate_digest"]:
                    raise Refuted("selected " + name + " certificate digest differs")
                retained = _child_evidence(raw, child_request, child_policy, module.CERTIFICATE_VERSION)
                certificates[name] = raw
                if retained is None:
                    unavailable = True
                    continue
                fields = ({"schema_version", "subject", "chain_certificate"} if name == "association"
                          else {"schema_version", "chain_certificate", "attestation"})
                retained = _record(retained, fields, "native child evidence")
                if retained["schema_version"] != module.EVIDENCE_VERSION:
                    raise Refuted("retained " + name + " evidence version differs")
                if name == "association":
                    _association_subject(retained["subject"], request)
                else:
                    _attestation(retained["attestation"], child_request, child_policy)
                chain = _chain_bytes(retained["chain_certificate"], child_request, child_policy)
                if chain is None:
                    unavailable = True
                else:
                    chains[name] = chain
                    if name == "association":
                        _association_intent(chain, child_request, child_policy)
            except Unavailable:
                unavailable = True
            except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
                failures.append("retained " + name + " selection or intent contradicts external binding")
        if len(chains) == 2 and chains["association"] != chains["authenticity"]:
            failures.append("actual retained native chain certificate bytes differ")
        if failures:
            return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(set(failures))))
        if request["cancelled"]:
            raise Unavailable("selected computation cancelled after binding preflight")
        incomplete = unavailable or len(chains) != 2 or len(certificates) != 2
        if not certificates:
            raise Unavailable("required common native chain or child evidence unavailable")
        # The carried external pin is never replaced by an installed pin.
        # Delay source admission until all available retained contradictions,
        # retained common-chain comparisons and cancellation have been handled.
        # An absent peer cannot prevent replay of an independently usable child.
        source_unavailable = False
        try:
            if policy["mechanism_digest"] != mechanism_digest():
                failures.append("selected policy differs from installed mechanism")
        except (OSError, ImportError, MemoryError, CancelledError, RecursionError, OverflowError):
            source_unavailable = True
        except Exception:
            source_unavailable = True
        statuses, outage = {}, source_unavailable
        for name in ("association", "authenticity"):
            if name not in certificates:
                statuses[name] = "UNKNOWN"
                continue
            status, missing_backend = _native_replay(name, certificates[name],
                request[name + "_request"], policy[name + "_policy"])
            statuses[name] = status
            outage = outage or missing_backend
        observations = {**_observations(request), "native_statuses": statuses}
        if failures or "FAIL" in statuses.values():
            detail = "; ".join(sorted(set(failures))) if failures else "native composed prerequisite refuted"
            return MechanismDecision(MechanismOutcome.FAIL, detail, observations)
        if incomplete or source_unavailable or "UNKNOWN" in statuses.values():
            if outage:
                observations["checking_dependency"] = "NATIVE_REPLAY_UNAVAILABLE"
            detail = ("required common native chain or child evidence unavailable" if incomplete
                      else "native composed prerequisite unavailable")
            return MechanismDecision(MechanismOutcome.UNKNOWN, detail, observations)
        return MechanismDecision(MechanismOutcome.PASS, _PASS_DETAILS, observations)
    except Unavailable as exc:
        if failures:
            return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(set(failures))))
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _selector_bytes(request: dict[str, Any]) -> bytes:
    return canonical_bytes({"schema_version": SELECTOR_VERSION, "independently_selected_request": request})


class _Mechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any], present: bool) -> None:
        self.request, self.policy, self.present = request, policy, present
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        parameters = {"request_digest": "sha256:" + canonical_digest(self.request),
                      "candidate_evidence_present": "true" if self.present else "false"}
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != parameters
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                or len(evidence) != 1 + int(self.present)
                or evidence[0] != _selector_bytes(self.request)):
            return MechanismDecision(MechanismOutcome.FAIL, "bound selected composed proposition differs")
        return _evaluate(evidence[1] if self.present else None, self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    present = request["evidence_ref"] in store
    selector = _selector_bytes(request)
    selector_ref = store.add(selector)
    if selector_ref == request["evidence_ref"]:
        raise VerifierComposedSecurityError("selector and candidate evidence identities must be distinct")
    refs = [selector_ref] + ([request["evidence_ref"]] if present else [])
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=tuple(refs), trust_roots=tuple(policy["trust_roots"]),
        # The fixed session admission ceiling permits selector contradictions to
        # be inspected before the separately selected candidate-byte allowance.
        bounds=EvidenceBounds(2, len(selector) + _MAX_EVIDENCE_BYTES),
        parameters={"request_digest": "sha256:" + canonical_digest(request),
                    "candidate_evidence_present": "true" if present else "false"},
    )
    session = VerificationSession(store)
    session.register(_Mechanism(request, policy, present))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "VERIFIER", "scope": SCOPE,
        "composed_security_admission": "UNKNOWN",
        "selected_signed_association": "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED},
        "evaluation": evaluation.to_dict(),
    }
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": refs,
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise VerifierComposedSecurityError("certificate byte bound exhausted")
    return encoded


def build_verifier_composed_security_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    admitted = _policy(policy)
    selected = _request(request, admitted)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _MAX_EVIDENCE_BYTES:
            raise VerifierComposedSecurityError("immutable bounded candidate evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise VerifierComposedSecurityError("candidate evidence differs from external selection")
    return _build(selected, admitted, store)


def _unavailable_result(carried: Any, current: dict[str, Any],
                        request: dict[str, Any]) -> dict[str, Any]:
    selected = _record(carried, set(current), "carried result")
    if selected["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
        raise VerifierComposedSecurityError("carried status differs")
    dynamic_result = {"status", "evaluation", "selected_signed_association"}
    if any(canonical_bytes(selected[key]) != canonical_bytes(current[key])
           for key in current if key not in dynamic_result):
        raise VerifierComposedSecurityError("carried claim-limit invariant differs")
    expected_association = "PASS" if selected["status"] == "PASS" else "NOT_ESTABLISHED"
    if selected["selected_signed_association"] != expected_association:
        raise VerifierComposedSecurityError("carried selected-association invariant differs")
    carried_evaluation = _record(selected["evaluation"], set(current["evaluation"]), "carried evaluation")
    if (carried_evaluation["outcome"] != selected["status"]
            or type(carried_evaluation["details"]) is not str
            or any(canonical_bytes(carried_evaluation[key]) != canonical_bytes(current["evaluation"][key])
                   for key in carried_evaluation if key not in {"outcome", "details", "observations"})):
        raise VerifierComposedSecurityError("carried evaluation binding differs")
    observations = carried_evaluation["observations"]
    if selected["status"] == "PASS":
        expected = {**_observations(request), "native_statuses": {"association": "PASS", "authenticity": "PASS"}}
        if carried_evaluation["details"] != _PASS_DETAILS or canonical_bytes(observations) != canonical_bytes(expected):
            raise VerifierComposedSecurityError("carried positive observations differ")
    elif observations:
        row = _record(observations, set(_observations(request)) | {"native_statuses"}
                      | ({"checking_dependency"} if "checking_dependency" in observations else set()), "carried observations")
        if any(row[key] != value for key, value in _observations(request).items()):
            raise VerifierComposedSecurityError("carried negative bindings differ")
        statuses = _record(row["native_statuses"], {"association", "authenticity"}, "native statuses")
        if (any(type(value) is not str or value not in {"PASS", "FAIL", "UNKNOWN"} for value in statuses.values())
                or row.get("checking_dependency", "NATIVE_REPLAY_UNAVAILABLE") != "NATIVE_REPLAY_UNAVAILABLE"):
            raise VerifierComposedSecurityError("carried negative observations differ")
    return {**current, "replay_status": "UNAVAILABLE"}


def recheck_verifier_composed_security_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    admitted = _policy(policy)
    selected = _request(expected_request, admitted)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise VerifierComposedSecurityError("immutable bounded certificate required")
    try:
        envelope = _record(_json(certificate_bytes), _ENVELOPE_FIELDS, "certificate")
        selector = _selector_bytes(selected)
        selector_ref = _hash(selector)
        payloads = envelope["evidence_payloads"]
        if type(payloads) is not dict:
            raise VerifierComposedSecurityError("retained payload map differs")
        present = selected["evidence_ref"] in payloads
        refs = [selector_ref] + ([selected["evidence_ref"]] if present else [])
        if (envelope["schema_version"] != CERTIFICATE_VERSION
                or envelope["digest"] != "sha256:" + canonical_digest({
                    key: value for key, value in envelope.items() if key != "digest"})
                or canonical_bytes(envelope["request"]) != canonical_bytes(selected)
                or envelope["policy_digest"] != selected["policy_digest"]
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_refs"] != refs or set(payloads) != set(refs)):
            raise VerifierComposedSecurityError("certificate differs from external selection")
        store = EvidenceStore()
        for ref in refs:
            raw = _b64(payloads[ref], len(selector) if ref == selector_ref else _MAX_EVIDENCE_BYTES)
            if store.add(raw) != ref:
                raise VerifierComposedSecurityError("retained evidence commitment differs")
        if store.resolve(selector_ref) != selector:
            raise VerifierComposedSecurityError("retained selector differs")
        rebuilt = _build(selected, admitted, store)
        current = strict_json_loads(rebuilt.decode("utf-8"))["result"]
        if rebuilt == certificate_bytes:
            return {**current, "replay_status": "REPRODUCED"}
        observations = current["evaluation"]["observations"]
        if (current["status"] == "UNKNOWN"
                and observations.get("checking_dependency") == "NATIVE_REPLAY_UNAVAILABLE"):
            return _unavailable_result(envelope["result"], current, selected)
        raise VerifierComposedSecurityError("certificate result does not reproduce exactly")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, Unavailable) as exc:
        if isinstance(exc, VerifierComposedSecurityError):
            raise
        raise VerifierComposedSecurityError("composed-security certificate cannot replay") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "REQUEST_VERSION", "POLICY_VERSION",
    "EVIDENCE_VERSION", "CERTIFICATE_VERSION", "CONTEXT_VERSION", "PROPOSITION_DIGEST",
    "VerifierComposedSecurityDescriptor", "VerifierComposedSecurityError",
    "registration", "context_binding", "context_digest", "mechanism_digest",
    "verifier_composed_security_policy", "verifier_composed_security_request",
    "build_verifier_composed_security_certificate", "recheck_verifier_composed_security_certificate",
]
