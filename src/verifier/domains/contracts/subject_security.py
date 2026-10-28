"""Current typed-subject inclusion in an externally anchored finite receipt chain.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte budgets measure octets, sequence and objective
indices are dimensionless. This mechanism proves selected retained association,
not issuer authenticity, actual execution, enforcement or full security closure.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
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
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import receipt_chain, retained_selection

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-subject-security-request-1"
POLICY_VERSION = "verifier-current-subject-security-policy-1"
EVIDENCE_VERSION = "verifier-current-subject-security-evidence-1"
CERTIFICATE_VERSION = "verifier-current-subject-security-certificate-1"
MESSAGE_VERSION = "verifier-current-subject-security-message-1"
MECHANISM_ID = "verifier.current-object.selected-subject-receipt-binding.1"
SCOPE = "exact_typed_subject_in_selected_finite_receipt_chain"
_MAX_EVIDENCE = 4 * 1024 * 1024
_MAX_CERTIFICATE = 8 * 1024 * 1024
_MAX_SEQUENCE = (1 << 63) - 1


class SubjectSecurityError(ValueError):
    """Malformed external selection, unsupported policy or substituted certificate."""


def _kind(value: Any) -> str:
    if type(value) is not str or value not in {kind.value for kind in ObjectKind}:
        raise SubjectSecurityError("exact admitted namespace kind required")
    return value


def coordinate(kind: str) -> str:
    """Reserve the existing RECEIPT-9.1 and RECEIPT-9.2 meanings unchanged."""
    return _kind(kind) + ("-9.3" if kind == "RECEIPT" else "-9.1")


def registration(kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": coordinate(kind),
        "subject_kind": kind, "scope": SCOPE,
        "proposition": "The exact externally selected " + kind + " namespace record is the sole direct subject of the selected RECEIPT record, and the selected sequence entry in its natively replayed finite chain equals canonical typed-subject intent binding that record, objective, receipt identifier, domain, genesis, position, context and policy.",
        "prerequisites": ["externally selected exact subject and receipt-chain request, certificate and policy", "externally retained chain anchors, entry sequence and context commitment"],
        "exclusions": ["issuer authenticity or digital-signature validity", "payload truth, actual execution or enforcement", "freshness or one-time consumption of context", "typed-composition closure or hardware authenticity", "privacy, consent, governance or public disclosure authority", "complete security tier or object-profile conformance"],
    }


@dataclass(frozen=True)
class SubjectSecurityDescriptor:
    """Immutable public-route metadata for one exact kind-specific proposition."""
    kind: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return "sha256:" + canonical_digest(registration(self.kind))


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SubjectSecurityError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SubjectSecurityError)


def _name(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise SubjectSecurityError("bounded nonempty identifier required")
    return value


def _sequence(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SEQUENCE:
        raise SubjectSecurityError("bounded plain integer sequence required")
    return value


def mechanism_digest(object_kind: str) -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["specification"] = Path(__file__).parents[2] / "standard" / "CURRENT_SUBJECT_SECURITY.md"
    return "sha256:" + canonical_digest({
        "object_kind": _kind(object_kind),
        **{name: hashlib.sha256(path.read_bytes()).hexdigest()
           for name, path in sorted(paths.items())},
        "receipt_chain_mechanism": receipt_chain.mechanism_digest(),
    })


def _chain_policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes"}, "chain policy")
    admitted = receipt_chain.receipt_chain_policy(
        trust_roots=selected["trust_roots"], max_certificate_bytes=selected["max_certificate_bytes"])
    if canonical_bytes(selected) != canonical_bytes(admitted):
        raise SubjectSecurityError("selected chain policy differs from installed prerequisite")
    return admitted


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes", "chain_policy", "object_kind"}, "policy")
    kind = _kind(selected.pop("object_kind"))
    child = _chain_policy(selected.pop("chain_policy"))
    admitted = retained_selection.policy(selected, error_type=SubjectSecurityError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=lambda: mechanism_digest(kind), max_certificate_bytes=_MAX_CERTIFICATE)
    return {**admitted, "chain_policy": child, "object_kind": kind}


def subject_security_policy(*, object_kind: str, chain_policy: dict[str, Any], trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE) -> dict[str, Any]:
    """Retain external anchor selection; root labels grant no authenticity."""
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(object_kind), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "chain_policy": chain_policy,
        "object_kind": object_kind})


def _chain_request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "receipt_object_id", "receipt_object_digest", "domain",
        "genesis_digest", "first_sequence", "tip_digest", "evidence_ref", "policy_digest",
        "max_entries", "max_evidence_bytes"}, "chain request")
    keys = ("receipt_object_id", "receipt_object_digest", "domain", "genesis_digest",
            "first_sequence", "tip_digest", "evidence_ref", "max_entries", "max_evidence_bytes")
    admitted = receipt_chain.receipt_chain_request(
        **{key: selected[key] for key in keys}, policy=policy["chain_policy"])
    if canonical_bytes(selected) != canonical_bytes(admitted):
        raise SubjectSecurityError("selected chain request differs from prerequisite")
    return admitted


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest", "context_digest",
        "chain_request", "chain_certificate_digest", "chain_sequence", "evidence_ref",
        "policy_digest", "max_evidence_bytes"}, "request")
    kind = _kind(selected["object_kind"])
    if kind != policy["object_kind"]:
        raise SubjectSecurityError("selected policy belongs to a different object kind")
    for key, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                          ("coordinate", coordinate(kind)), ("proposition_digest", SubjectSecurityDescriptor(kind).PROPOSITION_DIGEST)):
        if type(selected[key]) is not str or selected[key] != expected:
            raise SubjectSecurityError("selected typed-subject objective differs")
    _name(selected["subject_id"])
    for key in ("object_digest", "context_digest", "chain_certificate_digest", "evidence_ref", "policy_digest"):
        _digest(selected[key])
    if selected["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SubjectSecurityError("request differs from selected policy")
    child = _chain_request(selected["chain_request"], policy)
    position = _sequence(selected["chain_sequence"])
    if not child["first_sequence"] <= position < child["first_sequence"] + child["max_entries"]:
        raise SubjectSecurityError("selected entry is outside finite chain selection")
    size = selected["max_evidence_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_EVIDENCE:
        raise SubjectSecurityError("selected evidence byte budget is unsupported")
    selected["chain_request"] = child
    return selected


def subject_security_request(*, object_kind: str, subject_id: str, object_digest: str,
        context_digest: str, chain_request: dict[str, Any], chain_certificate_digest: str,
        chain_sequence: int, evidence_ref: str, policy: dict[str, Any],
        max_evidence_bytes: int = _MAX_EVIDENCE) -> dict[str, Any]:
    admitted = _policy(policy)
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(object_kind), "proposition_digest": SubjectSecurityDescriptor(object_kind).PROPOSITION_DIGEST,
        "object_kind": object_kind, "subject_id": subject_id, "object_digest": object_digest,
        "context_digest": context_digest, "chain_request": chain_request,
        "chain_certificate_digest": chain_certificate_digest, "chain_sequence": chain_sequence,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "max_evidence_bytes": max_evidence_bytes}, admitted)


def subject_security_message(*, object_kind: str, subject_id: str, object_digest: str,
        receipt_object_id: str, domain: str, genesis_digest: str, first_sequence: int,
        sequence: int, context_digest: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Format intent before chaining it; no tip or evidence digest creates a cycle."""
    kind = _kind(object_kind)
    admitted = _policy(policy)
    if kind != admitted["object_kind"]:
        raise SubjectSecurityError("message policy belongs to a different object kind")
    if type(domain) is not str or not domain.strip() or len(domain.encode("utf-8")) > 256:
        raise SubjectSecurityError("bounded chain domain required")
    first, position = _sequence(first_sequence), _sequence(sequence)
    if not first <= position < first + 64:
        raise SubjectSecurityError("entry cannot lie in admitted finite chain ceiling")
    return {"schema_version": MESSAGE_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind), "proposition_digest": SubjectSecurityDescriptor(kind).PROPOSITION_DIGEST,
        "object_kind": kind, "subject_id": _name(subject_id), "object_digest": _digest(object_digest),
        "receipt_object_id": _name(receipt_object_id), "chain_domain": domain,
        "chain_genesis_digest": _digest(genesis_digest), "chain_first_sequence": first,
        "chain_sequence": position, "context_digest": _digest(context_digest),
        "policy_digest": "sha256:" + canonical_digest(admitted)}


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "subject", "chain_certificate"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        record = _record(value["subject"], {"object_id", "kind", "payload", "operands"}, "subject")
        if type(record["operands"]) is not dict:
            raise Refuted("subject operands require an exact namespace map")
        item = NamespaceObject.create(**record)
        if (canonical_bytes(item.to_dict()) != canonical_bytes(record)
                or item.object_id != request["subject_id"] or item.kind.value != request["object_kind"]
                or item.digest != request["object_digest"]):
            raise Refuted("retained subject differs from exact external selection")
        if value["chain_certificate"] is None:
            raise Unavailable("retained selected receipt-chain certificate absent")
        if type(value["chain_certificate"]) is not str:
            raise Refuted("retained chain certificate must be exact text or null")
        child = value["chain_certificate"].encode("utf-8")
        if len(child) > policy["chain_policy"]["max_certificate_bytes"]:
            raise Unavailable("retained chain certificate byte bound exhausted")
        if "sha256:" + hashlib.sha256(child).hexdigest() != request["chain_certificate_digest"]:
            raise Refuted("retained chain certificate differs from external selection")
        native = receipt_chain.recheck_receipt_chain_certificate(child,
            expected_request=request["chain_request"], policy=policy["chain_policy"])
        if native["status"] == "FAIL":
            raise Refuted("selected receipt-chain prerequisite refuted")
        if native["status"] != "PASS":
            raise Unavailable("selected receipt-chain prerequisite unavailable")
        child_envelope = strict_json_loads(child.decode("utf-8"))
        chain = strict_json_loads(base64.b64decode(child_envelope["evidence_payloads"][request["chain_request"]["evidence_ref"]], validate=True).decode("utf-8"))
        if chain["receipt_object"]["operands"].get("subject") != [request["subject_id"]]:
            raise Refuted("selected RECEIPT is not directly bound to this sole subject")
        offset = request["chain_sequence"] - request["chain_request"]["first_sequence"]
        if offset >= len(chain["entries"]):
            raise Refuted("selected entry does not occur in retained finite chain")
        message_bytes = base64.b64decode(chain["entries"][offset]["receipt_base64"], validate=True)
        expected = subject_security_message(object_kind=request["object_kind"],
            subject_id=request["subject_id"], object_digest=request["object_digest"],
            receipt_object_id=request["chain_request"]["receipt_object_id"], domain=request["chain_request"]["domain"],
            genesis_digest=request["chain_request"]["genesis_digest"], first_sequence=request["chain_request"]["first_sequence"],
            sequence=request["chain_sequence"], context_digest=request["context_digest"], policy=policy)
        if message_bytes != canonical_bytes(expected):
            raise Refuted("selected retained entry differs from exact typed-subject intent")
        return MechanismDecision(MechanismOutcome.PASS, "selected typed subject and retained chain entry agree",
            {"object_digest": item.digest, "receipt_object_digest": request["chain_request"]["receipt_object_digest"],
             "chain_sequence": request["chain_sequence"], "context_digest": request["context_digest"]})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _Mechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}):
            return MechanismDecision(MechanismOutcome.FAIL, "bound typed-subject proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained subject-chain evidence bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"],
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_Mechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "security_tier_conformance": "NOT_ESTABLISHED",
        "issuer_authenticity": "NOT_ESTABLISHED", "signature_validity": "NOT_ESTABLISHED",
        "typed_composition_conformance": "NOT_ESTABLISHED", "hardware_authenticity": "NOT_ESTABLISHED",
        "context_consumption": "NOT_ESTABLISHED", "public_disclosure_authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": request["proposition_digest"], "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64([request["evidence_ref"]] if request["evidence_ref"] in store else []),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SubjectSecurityError("certificate byte bound exhausted")
    return encoded


def build_subject_security_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    admitted = _policy(policy)
    selected = _request(request, admitted)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _MAX_EVIDENCE:
            raise SubjectSecurityError("bounded immutable evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SubjectSecurityError("evidence differs from externally selected reference")
    return _build(selected, admitted, store)


def recheck_subject_security_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    admitted = _policy(policy)
    selected = _request(expected_request, admitted)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SubjectSecurityError("bounded immutable certificate required")
    try:
        envelope = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
             "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(envelope) != certificate_bytes or envelope["schema_version"] != CERTIFICATE_VERSION
                or _digest(envelope["digest"]) != "sha256:" + canonical_digest({key: value for key, value in envelope.items() if key != "digest"})
                or canonical_bytes(envelope["request"]) != canonical_bytes(selected)
                or envelope["policy_digest"] != selected["policy_digest"]
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != selected["proposition_digest"]
                or envelope["evidence_refs"] != [selected["evidence_ref"]]):
            raise SubjectSecurityError("certificate differs from external selection")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]}
                or any(type(value) is not str for value in payloads.values())):
            raise SubjectSecurityError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SubjectSecurityError("certificate result does not reproduce")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SubjectSecurityError):
            raise
        raise SubjectSecurityError("typed-subject certificate cannot replay") from exc
