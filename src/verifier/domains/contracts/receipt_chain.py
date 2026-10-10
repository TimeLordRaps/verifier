"""One bounded current RECEIPT-9.1 hash-chain objective.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Sequence counts are dimensionless; byte limits
measure exact retained or encoded bytes. A hash chain is not an issuer signature.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
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
COORDINATE = "RECEIPT-9.1"
EVIDENCE_VERSION = "verifier-receipt-chain-evidence-1"
LINK_VERSION = "verifier-receipt-chain-link-1"
REQUEST_VERSION = "verifier-current-receipt-chain-request-1"
POLICY_VERSION = "verifier-current-receipt-chain-policy-1"
CERTIFICATE_VERSION = "verifier-current-receipt-chain-certificate-1"
MECHANISM_ID = "verifier.current-receipt.selected-hash-chain.1"
PROPOSITION = (
    "For an externally selected RECEIPT namespace-object identifier and record digest, "
    "domain, genesis digest, first sequence and tip digest, the retained bounded "
    "canonical evidence reconstructs that exact RECEIPT object with matching chain "
    "anchors and a nonempty contiguous sequence of exact receipt byte strings. "
    "Recomputing each domain-separated link reaches precisely the selected tip."
)
REGISTRATION = {
    "schema_version": "verifier-current-object-proposition-1",
    "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
    "subject_kind": "RECEIPT", "proposition": PROPOSITION,
    "scope": "externally_selected_finite_receipt_hash_chain",
    "prerequisites": ["externally retained trusted RECEIPT object, domain, genesis, first sequence and tip"],
    "exclusions": ["issuer authenticity", "signature validity", "collision-resistance proof",
                   "history before genesis or after tip", "unavailable evidence detection",
                   "whole tier or object profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(REGISTRATION)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_ENTRIES = 64
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
_MAX_SEQUENCE = (1 << 63) - 1


class ReceiptChainError(ValueError):
    """Malformed selection, policy, or certificate; no verdict is promoted."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str for key in value)):
        raise ReceiptChainError(f"{label} fields differ")
    if set(value) != fields:
        raise ReceiptChainError(f"{label} fields differ")
    return dict(value)


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ReceiptChainError(f"{label} requires canonical SHA-256 digest")
    return value


def _domain(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 256:
        raise ReceiptChainError("domain requires bounded nonempty text")
    return value


def _object_id(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ReceiptChainError("receipt object identifier requires bounded nonempty text")
    return value


def mechanism_digest() -> str:
    """Bind the exact installed checker and its direct parsing/checking contracts."""
    sources = {
        "receipt_chain.py": Path(__file__),
        "namespace.py": Path(namespace_module.__file__),
        "evidence.py": Path(evidence_module.__file__),
        "certificate.py": Path(certificate_module.__file__),
        "receipt.py": Path(receipt_module.__file__),
        "common.py": Path(common_module.__file__),
        "CURRENT_RECEIPT_CHAIN.md": Path(__file__).parents[2] / "standard" / "CURRENT_RECEIPT_CHAIN.md",
    }
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest()
                                         for name, path in sorted(sources.items())})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
                               "trust_roots", "max_certificate_bytes"}, "policy")
    roots = selected["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ReceiptChainError("policy trust roots require sorted unique bounded labels")
    if (type(selected["schema_version"]) is not str
            or type(selected["mechanism_id"]) is not str
            or selected["schema_version"] != POLICY_VERSION
            or selected["mechanism_id"] != MECHANISM_ID
            or _digest(selected["mechanism_digest"], "mechanism") != mechanism_digest()):
        raise ReceiptChainError("policy does not select installed mechanism")
    size = selected["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ReceiptChainError("certificate byte bound is unsupported")
    selected["trust_roots"] = list(roots)
    return selected


def receipt_chain_policy(*, trust_roots: Sequence[str],
                         max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format a policy; labels do not authenticate their issuer."""
    if type(trust_roots) not in (list, tuple):
        raise ReceiptChainError("policy trust roots require a plain sequence")
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": list(trust_roots),
                    "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
                               "proposition_digest", "receipt_object_id",
                               "receipt_object_digest", "domain", "genesis_digest",
                               "first_sequence", "tip_digest", "evidence_ref",
                               "policy_digest", "max_entries", "max_evidence_bytes"}, "request")
    if (type(selected["schema_version"]) is not str
            or type(selected["semantic_version"]) is not str
            or type(selected["coordinate"]) is not str
            or selected["schema_version"] != REQUEST_VERSION
            or selected["semantic_version"] != SEMANTIC_VERSION
            or selected["coordinate"] != COORDINATE
            or _digest(selected["proposition_digest"], "proposition") != PROPOSITION_DIGEST):
        raise ReceiptChainError("current receipt-chain objective differs")
    _domain(selected["domain"])
    _object_id(selected["receipt_object_id"])
    for name in ("receipt_object_digest", "genesis_digest", "tip_digest",
                 "evidence_ref", "policy_digest"):
        _digest(selected[name], name)
    first = selected["first_sequence"]
    count = selected["max_entries"]
    size = selected["max_evidence_bytes"]
    if (type(first) is not int or not 0 <= first <= _MAX_SEQUENCE
            or type(count) is not int or not 1 <= count <= _MAX_ENTRIES
            or type(size) is not int or not 1 <= size <= _MAX_EVIDENCE_BYTES):
        raise ReceiptChainError("selected sequence or finite limits are unsupported")
    return selected


def receipt_chain_request(*, domain: str, genesis_digest: str, first_sequence: int,
                          tip_digest: str, evidence_ref: str,
                          receipt_object_id: str, receipt_object_digest: str,
                          policy: dict[str, Any],
                          max_entries: int = _MAX_ENTRIES,
                          max_evidence_bytes: int = _MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    """Format intent; only external retention/selection makes it authoritative."""
    admitted = _policy(policy)
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
                     "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
                     "receipt_object_id": receipt_object_id,
                     "receipt_object_digest": receipt_object_digest,
                     "domain": domain, "genesis_digest": genesis_digest,
                     "first_sequence": first_sequence, "tip_digest": tip_digest,
                     "evidence_ref": evidence_ref,
                     "policy_digest": "sha256:" + canonical_digest(admitted),
                     "max_entries": max_entries, "max_evidence_bytes": max_evidence_bytes})


def _evaluate_chain(data: bytes, request: Mapping[str, Any]) -> MechanismDecision:
    if len(data) > request["max_evidence_bytes"]:
        raise Unavailable("retained evidence byte bound exhausted")
    try:
        value = strict_json_loads(data.decode("utf-8"))
        row = _record(value, {"schema_version", "domain", "receipt_object",
                              "entries"}, "evidence")
        if canonical_bytes(row) != data:
            raise Refuted("retained evidence is not canonical")
        if row["schema_version"] != EVIDENCE_VERSION or row["domain"] != request["domain"]:
            raise Refuted("retained evidence version or domain differs")
        object_row = _record(row["receipt_object"],
                             {"object_id", "kind", "payload", "operands"},
                             "receipt namespace object")
        if object_row["kind"] != ObjectKind.RECEIPT.value:
            raise Refuted("retained namespace object is not RECEIPT")
        receipt_object = NamespaceObject.create(
            object_row["object_id"], object_row["kind"],
            object_row["payload"], object_row["operands"])
        if canonical_bytes(receipt_object.to_dict()) != canonical_bytes(object_row):
            raise Refuted("retained RECEIPT object is not an exact canonical namespace record")
        if (receipt_object.object_id != request["receipt_object_id"]
                or receipt_object.digest != request["receipt_object_digest"]):
            raise Refuted("retained RECEIPT object differs from external selection")
        payload = receipt_object.payload
        if (type(payload["chain_first_sequence"]) is not int
                or any(type(payload[key]) is not str for key in (
                    "chain_domain", "chain_genesis_digest", "chain_tip_digest"))
                or payload != {
            "chain_domain": request["domain"],
            "chain_genesis_digest": request["genesis_digest"],
            "chain_first_sequence": request["first_sequence"],
            "chain_tip_digest": request["tip_digest"],
        }):
            raise Refuted("retained RECEIPT object chain anchors differ")
        entries = row["entries"]
        if type(entries) is not list or not entries:
            raise Refuted("retained chain requires at least one receipt")
        if len(entries) > request["max_entries"]:
            raise Unavailable("selected receipt-count bound exhausted")
        previous = request["genesis_digest"]
        for index, item in enumerate(entries):
            entry = _record(item, {"sequence", "receipt_base64"}, "receipt entry")
            sequence = entry["sequence"]
            if (type(sequence) is not int or sequence != request["first_sequence"] + index
                    or sequence > _MAX_SEQUENCE):
                raise Refuted("receipt sequence is not contiguous from selected first sequence")
            encoded = entry["receipt_base64"]
            if type(encoded) is not str or len(encoded) > 4 * ((_MAX_RECEIPT_BYTES + 2) // 3):
                raise Refuted("receipt byte representation exceeds bound")
            try:
                receipt = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise Refuted("receipt bytes are not canonical base64") from exc
            if len(receipt) > _MAX_RECEIPT_BYTES or base64.b64encode(receipt).decode("ascii") != encoded:
                raise Refuted("receipt bytes exceed bound or are not canonical base64")
            previous = "sha256:" + canonical_digest({
                "schema_version": LINK_VERSION, "domain": request["domain"],
                "sequence": sequence, "previous": previous,
                "receipt_digest": "sha256:" + hashlib.sha256(receipt).hexdigest()})
        if previous != request["tip_digest"]:
            raise Refuted("retained chain does not reach externally selected tip")
        return MechanismDecision(MechanismOutcome.PASS,
            "retained finite receipt sequence reaches selected tip",
            {"tip_digest": previous, "receipt_count": len(entries),
             "receipt_object_digest": receipt_object.digest})
    except Unavailable:
        raise
    except (Refuted, ReceiptChainError, UnicodeError, TypeError, ValueError, KeyError,
            OverflowError, RecursionError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ReceiptChainMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request = request
        self.policy = policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["receipt_object_id"]
                or binding.predicate != COORDINATE
                or binding.expected is not True
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                or dict(binding.parameters) != _parameters(self.request)):
            return MechanismDecision(MechanismOutcome.FAIL, "bound chain proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained chain is required")
        try:
            return _evaluate_chain(evidence[0], self.request)
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))


def _parameters(request: Mapping[str, Any]) -> dict[str, str]:
    return {key: str(request[key]) for key in (
        "semantic_version", "proposition_digest", "receipt_object_digest",
        "domain", "genesis_digest", "first_sequence", "tip_digest",
        "policy_digest", "max_entries", "max_evidence_bytes")}


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ReceiptChainError("request differs from independently selected policy")
    proposition = BoundProposition(subject_id=request["receipt_object_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ReceiptChainMechanism(request, policy))
    evaluation = session.evaluate(proposition)
    result = {"status": evaluation.outcome.value,
        "scope": "externally_selected_finite_receipt_hash_chain",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "RECEIPT", "proposition_digest": PROPOSITION_DIGEST,
        "tip_digest": request["tip_digest"],
        "receipt_object_id": request["receipt_object_id"],
        "receipt_object_digest": request["receipt_object_digest"],
        "object_profile_conformance": "NOT_ESTABLISHED",
        "issuer_authenticity": "NOT_ESTABLISHED",
        "signature_validity": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ReceiptChainError("certificate byte bound exhausted")
    return encoded


def build_receipt_chain_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    """Evaluate one selected chain and retain all available exact evidence."""
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != "sha256:" + canonical_digest(admitted):
        raise ReceiptChainError("request policy commitment differs")
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes:
            raise ReceiptChainError("retained evidence requires immutable bytes")
        if len(evidence_bytes) > _MAX_EVIDENCE_BYTES:
            raise Unavailable("retained evidence exceeds checker ceiling")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise Refuted("supplied evidence contradicts selected byte reference")
    return _build(selected, admitted, store)


def recheck_receipt_chain_certificate(certificate_bytes: bytes, *,
                                      expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    """Replay exact certificate bytes against independent request and policy."""
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ReceiptChainError("certificate is absent or exceeds selected byte bound")
    try:
        value = strict_json_loads(certificate_bytes.decode("utf-8"))
        if canonical_bytes(value) != certificate_bytes:
            raise ReceiptChainError("certificate is noncanonical")
        envelope = _record(value, {"schema_version", "request", "policy_digest",
            "mechanism_digest", "proposition_digest", "evidence_refs",
            "evidence_payloads", "result", "digest"}, "certificate")
        if envelope["schema_version"] != CERTIFICATE_VERSION:
            raise ReceiptChainError("unsupported receipt-chain certificate version")
        if (_digest(envelope["digest"], "certificate") != "sha256:" + canonical_digest({
                key: item for key, item in envelope.items() if key != "digest"})):
            raise ReceiptChainError("certificate digest differs")
        if envelope["request"] != selected:
            raise ReceiptChainError("certificate differs from externally selected request")
        if envelope["policy_digest"] != "sha256:" + canonical_digest(admitted):
            raise ReceiptChainError("certificate differs from externally selected policy")
        if (envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_refs"] != [selected["evidence_ref"]]):
            raise ReceiptChainError("certificate mechanism, proposition or evidence differs")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise ReceiptChainError("certificate embedded evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ReceiptChainError("certificate result does not reproduce")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (UnicodeError, TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        if isinstance(exc, ReceiptChainError):
            raise
        raise ReceiptChainError(f"invalid receipt-chain certificate: {exc}") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "PROPOSITION", "PROPOSITION_DIGEST", "ReceiptChainError",
           "receipt_chain_policy", "receipt_chain_request",
           "build_receipt_chain_certificate", "recheck_receipt_chain_certificate"]
