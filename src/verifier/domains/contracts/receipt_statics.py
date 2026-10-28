"""Current RECEIPT-3.1: canonical VSTD-1 claim-receipt byte statics.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8);
Boolean satisfiability problem (SAT). Byte limits measure exact retained bytes. Counts and operation budgets are
dimensionless. This checks retained bytes only: no claim truth, audit replay,
issuer authenticity or external referent is established here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, fields
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import checker as checker_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import provenance as provenance_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.checker import (
    GroundingVerdict, IndependenceBasis, IndependenceStatus, IndependentAuditReport,
    IndependentGroundingResult, IndependentSatResult, VerificationVerdict,
)
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import (
    CLAIM_RECEIPT_KIND, CLAIM_SCHEMA_VERSION, ClaimSpec, EvidencePayload,
    ExecutionMetadata, VstdReceipt, canonical_json_dumps, compute_canonical_digest,
    strict_json_loads,
)
from verifier.domains import common as common_module
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "RECEIPT-3.1"
REQUEST_VERSION = "verifier-current-receipt-statics-request-1"
POLICY_VERSION = "verifier-current-receipt-statics-policy-1"
CERTIFICATE_VERSION = "verifier-current-receipt-statics-certificate-1"
EVIDENCE_VERSION = "verifier-current-receipt-statics-evidence-1"
MECHANISM_ID = "verifier.current-receipt.vstd1-canonical-statics.1"
SCOPE = "selected_vstd1_receipt_canonical_statics"
RECORD_FIELDS = frozenset({"receipt_kind", "receipt_schema_version",
                           "receipt_sha256", "prerequisites"})
_CEILINGS = {"max_operations": 200000, "max_items": 4096,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_receipt_bytes": 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"-?(0|[1-9][0-9]*)\Z")


class ReceiptStaticsError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "RECEIPT", "scope": SCOPE,
        "proposition": (
            "The externally selected exact RECEIPT namespace record carries exactly "
            "receipt kind claim_mechanics, receipt schema version VSTD-1, the SHA-256 "
            "commitment of the retained receipt bytes and a sorted unique declared "
            "prerequisite identifier list. The retained bytes match that commitment, "
            "equal their VSTD-1 canonical JSON re-serialization, decode under the "
            "installed verifier.core.receipt VSTD-1 claim-mechanics model with exact "
            "field sets and value types and without serialized EVIDENCED independence, "
            "re-serialize from that model to the same bytes, and carry a canonical_digest "
            "equal to the SHA-256 of their canonical stable payload."),
        "prerequisites": [
            "externally selected RECEIPT record identifier and digest, exact retained "
            "receipt bytes and finite checker limits"],
        "exclusions": [
            "claim truth or audit verdict correctness; validation replay is RECEIPT-2.1",
            "bytes of source files, source artifacts or other external referents",
            "resolution of declared prerequisites; that is RECEIPT-4.1",
            "hash-chain continuity (RECEIPT-9.1) and issuer authenticity (RECEIPT-9.2)",
            "typed namespace composition of subject and hardware operands",
            "whole RECEIPT statics tier or object-profile conformance",
            "privacy, consent, governance, security, authority or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ReceiptStaticsDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, names: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, names, label, ReceiptStaticsError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, checker_module,
               provenance_module, namespace_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "VSTD-1.md", "CURRENT_RECEIPT_STATICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ReceiptStaticsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def receipt_statics_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format a policy; trust-root labels do not authenticate anyone."""
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def subject_text(value: Any, error_type: type[ValueError]) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise error_type("bounded RECEIPT subject identifier required")
    return value


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for name, expected in (("schema_version", REQUEST_VERSION),
                           ("semantic_version", SEMANTIC_VERSION),
                           ("coordinate", COORDINATE),
                           ("proposition_digest", PROPOSITION_DIGEST),
                           ("object_kind", "RECEIPT")):
        if type(selected[name]) is not str or selected[name] != expected:
            raise ReceiptStaticsError("selected RECEIPT statics objective differs")
    subject_text(selected["subject_id"], ReceiptStaticsError)
    for name in ("object_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(selected[name], ReceiptStaticsError)
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ReceiptStaticsError)
    return selected


def receipt_statics_request(*, subject_id: str, object_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    """Format intent; only external retention and selection make it authoritative."""
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ReceiptStaticsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "RECEIPT",
        "subject_id": subject_id, "object_digest": object_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


# VSTD-1 grammar. Field sets come from the installed dataclasses, so a model
# change moves both the admitted grammar and the bound mechanism digest.
def _names(model: type) -> set[str]:
    return {item.name for item in fields(model)}


def _row(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != names:
        raise Refuted(label + " fields differ from the admitted VSTD-1 model")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str:
        raise Refuted(label + " must be text")
    return value


def _flag(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise Refuted(label + " must be a boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        raise Refuted(label + " must be an integer")
    return value


def _texts(value: Any, label: str) -> list[str]:
    if type(value) is not list:
        raise Refuted(label + " must be a list of text")
    return [_text(item, label) for item in value]


def _text_map(value: Any, label: str) -> dict[str, str]:
    if type(value) is not dict:
        raise Refuted(label + " must be an object of text")
    return {key: _text(item, label) for key, item in value.items()}


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise Refuted(label + " must be a JSON object")
    return value


def _enum(kind: type, value: Any, label: str) -> Any:
    try:
        return kind(_text(value, label))
    except ValueError as exc:
        raise Refuted(label + " is outside the admitted VSTD-1 vocabulary") from exc


def _claim(value: Any) -> ClaimSpec:
    row = _row(value, _names(ClaimSpec), "claim")
    return ClaimSpec(**{name: _text(row[name], "claim " + name) for name in (
        "id", "title", "statement", "status", "scope", "falsification_condition",
        "last_verified")}, limitations=tuple(_texts(row["limitations"], "claim limitations")))


def _evidence(value: Any) -> EvidencePayload:
    row = _row(value, _names(EvidencePayload), "evidence")
    if type(row["clauses"]) is not list or any(type(clause) is not list for clause in row["clauses"]):
        raise Refuted("evidence clauses must be lists of integer literals")
    reasons = row["atomic_reasons"]
    if type(reasons) is not list or any(type(item) is not dict for item in reasons):
        raise Refuted("evidence atomic reasons must be JSON objects")
    return EvidencePayload(
        domain=_text(row["domain"], "evidence domain"),
        input_text_or_formula=_text(row["input_text_or_formula"], "evidence formula"),
        n_vars=_integer(row["n_vars"], "evidence n_vars"),
        clauses=tuple(tuple(_integer(literal, "clause literal") for literal in clause)
                      for clause in row["clauses"]),
        atomic_reasons=tuple(reasons),
        assumptions=tuple(_texts(row["assumptions"], "evidence assumptions")),
        source_artifacts=_text_map(row["source_artifacts"], "evidence source artifacts"))


def _basis(value: Any) -> IndependenceBasis:
    row = _row(value, _names(IndependenceBasis) | {"independently_verified"},
               "independence basis")
    _flag(row["independently_verified"], "independently_verified")
    statuses = {name: _enum(IndependenceStatus, row[name], name) for name in (
        "actor_independence", "implementation_separation", "runtime_separation")}
    if IndependenceStatus.EVIDENCED in statuses.values():
        raise Refuted("VSTD-1 rejects receipts that serialize EVIDENCED independence")
    return IndependenceBasis(**statuses,
                             evidence=tuple(_texts(row["evidence"], "independence evidence")))


def _sat(value: Any) -> IndependentSatResult:
    row = _row(value, _names(IndependentSatResult), "SAT result")
    model = _json_object(row["model"], "SAT model")
    assignment = {}
    for key, item in model.items():
        if _DECIMAL.fullmatch(key) is None:
            raise Refuted("SAT model variable must be a decimal integer")
        assignment[int(key)] = _flag(item, "SAT model value")
    conflict = row["conflicting_clause"]
    if conflict is not None:
        if type(conflict) is not list:
            raise Refuted("conflicting clause must be null or an integer list")
        conflict = [_integer(literal, "conflict literal") for literal in conflict]
    return IndependentSatResult(
        satisfiable=_flag(row["satisfiable"], "satisfiable"),
        verdict=_enum(VerificationVerdict, row["verdict"], "SAT verdict"),
        model=assignment, conflicting_clause=conflict,
        decisions_count=_integer(row["decisions_count"], "decisions_count"),
        propagations_count=_integer(row["propagations_count"], "propagations_count"))


def _grounding(value: Any) -> IndependentGroundingResult:
    row = _row(value, _names(IndependentGroundingResult), "grounding result")
    lists = {name: _texts(row[name], name) for name in (
        "leaves", "observed_leaves", "inferred_leaves", "placeholder_leaves",
        "unspecified_leaves", "undischarged_assumptions", "missing_parent_references")}
    return IndependentGroundingResult(
        grounding_status=_enum(GroundingVerdict, row["grounding_status"], "grounding status"),
        cycle_detected=_flag(row["cycle_detected"], "cycle_detected"),
        is_valid=_flag(row["is_valid"], "is_valid"),
        details=_text(row["details"], "grounding details"), **lists)


def _audit(value: Any) -> IndependentAuditReport:
    row = _row(value, _names(IndependentAuditReport), "independent audit")
    return IndependentAuditReport(
        claim_id=_text(row["claim_id"], "audit claim_id"),
        sat_result=_sat(row["sat_result"]),
        grounding_result=_grounding(row["grounding_result"]),
        structural_integrity_passed=_flag(row["structural_integrity_passed"],
                                          "structural_integrity_passed"),
        overall_verdict=_enum(VerificationVerdict, row["overall_verdict"], "overall verdict"),
        trusted_computing_base=_text_map(row["trusted_computing_base"],
                                         "trusted computing base"),
        audit_notes=_texts(row["audit_notes"], "audit notes"),
        independence_basis=_basis(row["independence_basis"]))


def _provenance(value: Any) -> ProvenanceRecord:
    row = _row(value, _names(ProvenanceRecord), "provenance")
    git = _row(row["git"], _names(GitProvenance), "git provenance")
    runtime = _row(row["runtime"], _names(RuntimeEnvironment), "runtime provenance")
    return ProvenanceRecord(
        **{name: _text(row[name], "provenance " + name) for name in (
            "target_name", "portable_repository_id", "local_repository_path",
            "captured_at_utc", "command_executed")},
        git=GitProvenance(
            commit_sha=_text(git["commit_sha"], "git commit"),
            branch=_text(git["branch"], "git branch"),
            is_dirty=_flag(git["is_dirty"], "git is_dirty"),
            dirty_files=tuple(_texts(git["dirty_files"], "git dirty files")),
            untracked_files=tuple(_texts(git["untracked_files"], "git untracked files")),
            remote_origin=_text(git["remote_origin"], "git remote")),
        runtime=RuntimeEnvironment(**{name: _text(runtime[name], "runtime " + name)
                                      for name in _names(RuntimeEnvironment)}),
        source_file_hashes=_text_map(row["source_file_hashes"], "source file hashes"))


def _execution(value: Any) -> ExecutionMetadata | None:
    if value is None:
        return None
    row = _row(value, _names(ExecutionMetadata), "execution metadata")
    elapsed = row["elapsed_ms"]
    if type(elapsed) not in (int, float):
        raise Refuted("execution elapsed_ms must be a JSON number")
    return ExecutionMetadata(
        executed_at_utc=_text(row["executed_at_utc"], "executed_at_utc"), elapsed_ms=elapsed,
        **{name: _text(row[name], name) for name in (
            "command_executed", "stdout_snippet", "stderr_snippet")})


def decode_vstd1_receipt(data: bytes, budget: Budget) -> VstdReceipt:
    """Decode exact canonical VSTD-1 claim receipt bytes or raise Refuted/Unavailable."""
    try:
        value = strict_json_loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Refuted("retained receipt bytes are not strict UTF-8 JSON") from exc
    common_module.inspect_structure(value, budget)
    if canonical_json_dumps(value).encode("utf-8") != data:
        raise Refuted("retained receipt bytes are not VSTD-1 canonical JSON")
    row = _row(value, _names(VstdReceipt), "receipt")
    if row["schema_version"] != CLAIM_SCHEMA_VERSION or row["receipt_kind"] != CLAIM_RECEIPT_KIND:
        raise Refuted("receipt schema version or kind is not the admitted VSTD-1 claim_mechanics")
    digest = row["canonical_digest"]
    if type(digest) is not str or _HEX.fullmatch(digest) is None:
        raise Refuted("receipt canonical_digest must be 64 lowercase hexadecimal digits")
    receipt = VstdReceipt(
        schema_version=CLAIM_SCHEMA_VERSION, receipt_kind=CLAIM_RECEIPT_KIND,
        receipt_id=_text(row["receipt_id"], "receipt_id"), claim=_claim(row["claim"]),
        evidence=_evidence(row["evidence"]),
        target_result=_json_object(row["target_result"], "target_result"),
        independent_audit=_audit(row["independent_audit"]),
        provenance=_provenance(row["provenance"]),
        reproducibility=_json_object(row["reproducibility"], "reproducibility"),
        canonical_digest=digest, execution_metadata=_execution(row["execution_metadata"]))
    budget.tick()
    if canonical_json_dumps(receipt.to_dict()).encode("utf-8") != data:
        raise Refuted("retained receipt differs from its admitted VSTD-1 model serialization")
    if compute_canonical_digest(receipt.get_stable_payload()) != digest:
        raise Refuted("receipt canonical_digest does not commit to its canonical stable payload")
    return receipt


def check_receipt_statics(receipt_object: Any, receipt_base64: Any, *, subject_id: str,
        object_digest: str, max_receipt_bytes: int,
        budget: Budget) -> tuple[NamespaceObject, VstdReceipt, bytes]:
    """The RECEIPT-3.1 predicate over one retained record and its exact bytes."""
    row = _row(receipt_object, {"object_id", "kind", "payload", "operands"},
               "retained RECEIPT namespace record")
    if row["kind"] != ObjectKind.RECEIPT.value:
        raise Refuted("retained namespace record is not RECEIPT")
    record = NamespaceObject.create(row["object_id"], row["kind"], row["payload"],
                                    row["operands"])
    if canonical_bytes(record.to_dict()) != canonical_bytes(row):
        raise Refuted("retained RECEIPT record is not an exact canonical namespace record")
    if record.object_id != subject_id or record.digest != object_digest:
        raise Refuted("retained RECEIPT record differs from external selection")
    payload = record.payload
    if type(payload) is not dict or set(payload) != RECORD_FIELDS:
        raise Refuted("RECEIPT record payload fields differ")
    if (payload["receipt_kind"] != CLAIM_RECEIPT_KIND
            or payload["receipt_schema_version"] != CLAIM_SCHEMA_VERSION):
        raise Refuted("RECEIPT record does not select the VSTD-1 claim_mechanics schema version")
    commitment = payload["receipt_sha256"]
    if type(commitment) is not str or _HASH.fullmatch(commitment) is None:
        raise Refuted("RECEIPT record commitment must be a canonical SHA-256 digest")
    declared = payload["prerequisites"]
    if (type(declared) is not list
            or any(type(item) is not str or not item.strip() or len(item) > 256
                   for item in declared)
            or declared != sorted(set(declared))):
        raise Refuted("declared prerequisites must be sorted unique bounded identifiers")
    if type(receipt_base64) is not str:
        raise Refuted("retained receipt bytes must be canonical base64")
    if len(receipt_base64) > 4 * ((max_receipt_bytes + 2) // 3):
        raise Unavailable("selected receipt byte bound exhausted")
    receipt_bytes = decode_b64(receipt_base64, "retained receipt bytes")
    if len(receipt_bytes) > max_receipt_bytes:
        raise Unavailable("selected receipt byte bound exhausted")
    if "sha256:" + hashlib.sha256(receipt_bytes).hexdigest() != commitment:
        raise Refuted("retained receipt bytes differ from the RECEIPT record commitment")
    return record, decode_vstd1_receipt(receipt_bytes, budget), receipt_bytes


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        if len(data) > limits["max_evidence_bytes"]:
            raise Unavailable("retained evidence byte bound exhausted")
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "receipt_object", "receipt_base64"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained statics evidence differs")
        budget = Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        record, receipt, receipt_bytes = check_receipt_statics(
            value["receipt_object"], value["receipt_base64"],
            subject_id=request["subject_id"], object_digest=request["object_digest"],
            max_receipt_bytes=limits["max_receipt_bytes"], budget=budget)
        return MechanismDecision(MechanismOutcome.PASS,
            "retained VSTD-1 receipt bytes are canonical, schema-valid and digest-bound",
            {"receipt_id": receipt.receipt_id, "receipt_bytes": len(receipt_bytes),
             "record_digest": record.digest, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except RecursionError:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "checker recursion ceiling exhausted")
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ReceiptStaticsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound RECEIPT statics proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected receipt bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ReceiptStaticsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ReceiptStaticsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "RECEIPT", "scope": SCOPE,
        "receipt_canonical_statics": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED"),
        "claim_truth": "NOT_ESTABLISHED",
        "audit_validation_replay": "NOT_ESTABLISHED",
        "external_referent_bytes": "NOT_ESTABLISHED",
        "prerequisite_resolution": "NOT_ESTABLISHED",
        "hash_chain_continuity": "NOT_ESTABLISHED",
        "issuer_authenticity": "NOT_ESTABLISHED",
        "typed_composition": "NOT_ESTABLISHED",
        "whole_receipt_statics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
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
        raise ReceiptStaticsError("certificate byte bound exhausted")
    return encoded


def build_receipt_statics_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    """Evaluate one selected receipt and retain its exact available evidence."""
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ReceiptStaticsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ReceiptStaticsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_receipt_statics_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Replay exact certificate bytes against independent request and policy."""
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ReceiptStaticsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ReceiptStaticsError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ReceiptStaticsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ReceiptStaticsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ReceiptStaticsError):
            raise
        raise ReceiptStaticsError("invalid retained RECEIPT statics certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "PROPOSITION_DIGEST", "RECORD_FIELDS", "ReceiptStaticsDescriptor",
           "ReceiptStaticsError", "registration", "receipt_statics_policy",
           "receipt_statics_request", "decode_b64", "decode_vstd1_receipt",
           "check_receipt_statics", "build_receipt_statics_certificate",
           "recheck_receipt_statics_certificate"]
