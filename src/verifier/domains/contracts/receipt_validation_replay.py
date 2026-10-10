"""Current RECEIPT-2.1: replay of a retained VSTD-1 independent audit.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Boolean satisfiability problem (SAT); trusted computing
base (TCB); Davis-Putnam-Logemann-Loveland (DPLL). Byte limits measure exact
retained bytes. Counts, search steps and operation budgets are dimensionless.
Replay agreement is not claim truth, actor independence or authenticity.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import checker as checker_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.checker import IndependentAuditor, UNAVAILABLE_PREFIX
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import canonical_json_dumps, strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import receipt_statics, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "RECEIPT-2.1"
REQUEST_VERSION = "verifier-current-receipt-validation-replay-request-1"
POLICY_VERSION = "verifier-current-receipt-validation-replay-policy-1"
CERTIFICATE_VERSION = "verifier-current-receipt-validation-replay-certificate-1"
EVIDENCE_VERSION = "verifier-current-receipt-validation-replay-evidence-1"
MECHANISM_ID = "verifier.current-receipt.vstd1-audit-replay.1"
SCOPE = "selected_vstd1_receipt_audit_replay"
# Replayed report fields in the order a mismatch is reported. The declared
# independence basis is excluded: the same-process auditor never derives it.
REPLAYED_FIELDS = ("claim_id", "trusted_computing_base", "sat_result",
                   "grounding_result", "structural_integrity_passed",
                   "overall_verdict", "audit_notes")
_CEILINGS = {"max_operations": 200000, "max_items": 4096,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_receipt_bytes": 1024 * 1024, "max_sat_variables": 64,
             "max_search_steps": 50_000_000, "max_reasons": 256}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_STANDARD = Path(__file__).parents[2] / "standard"


class ReceiptValidationReplayError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "RECEIPT", "scope": SCOPE,
        "proposition": (
            "The externally selected RECEIPT record and its retained receipt bytes "
            "satisfy the RECEIPT-3.1 canonical statics predicate, and replaying the "
            "installed verifier.core.checker.IndependentAuditor.audit_claim_derivation "
            "on the receipt's retained claim identifier, variable count, clauses, "
            "atomic reasons and assumptions, with the externally selected expected "
            "satisfiability, reproduces the retained independent audit's claim "
            "identifier, trusted computing base digests, SAT result, grounding "
            "result, structural integrity flag, overall verdict and audit notes "
            "exactly under VSTD-1 canonical JSON."),
        "prerequisites": [
            "externally selected RECEIPT record identifier and digest, exact retained "
            "receipt bytes, the claim's expected satisfiability and finite checker limits"],
        "exclusions": [
            "claim truth; replay agreement shows reproduction, not correctness",
            "the declared independence basis, which the same-process auditor never derives",
            "the target solver's own result and any rerun of the target command",
            "bytes of source files, source artifacts or other external referents",
            "receipt generation, revocation event logging and ledger registration",
            "resolution of declared prerequisites; that is RECEIPT-4.1",
            "hash-chain continuity (RECEIPT-9.1) and issuer authenticity (RECEIPT-9.2)",
            "whole RECEIPT dynamics tier or object-profile conformance",
            "privacy, consent, governance, security, authority or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ReceiptValidationReplayDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, names: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, names, label, ReceiptValidationReplayError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, checker_module,
               common_module, retained_selection, receipt_statics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "VSTD-1.md", "CURRENT_RECEIPT_STATICS.md",
                 "CURRENT_RECEIPT_VALIDATION_REPLAY.md"):
        paths[name] = _STANDARD / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())}
        | {"receipt_statics_mechanism": receipt_statics.mechanism_digest()})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ReceiptValidationReplayError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def receipt_validation_replay_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format a policy; trust-root labels do not authenticate anyone."""
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "expected_satisfiable", "evidence_ref", "policy_digest", "limits"}, "request")
    for name, expected in (("schema_version", REQUEST_VERSION),
                           ("semantic_version", SEMANTIC_VERSION),
                           ("coordinate", COORDINATE),
                           ("proposition_digest", PROPOSITION_DIGEST),
                           ("object_kind", "RECEIPT")):
        if type(selected[name]) is not str or selected[name] != expected:
            raise ReceiptValidationReplayError("selected RECEIPT replay objective differs")
    receipt_statics.subject_text(selected["subject_id"], ReceiptValidationReplayError)
    if type(selected["expected_satisfiable"]) is not bool:
        raise ReceiptValidationReplayError("expected satisfiability must be a boolean")
    for name in ("object_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(selected[name], ReceiptValidationReplayError)
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ReceiptValidationReplayError)
    return selected


def receipt_validation_replay_request(*, subject_id: str, object_digest: str,
        expected_satisfiable: bool, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    """Format intent; only external retention and selection make it authoritative."""
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ReceiptValidationReplayError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "RECEIPT",
        "subject_id": subject_id, "object_digest": object_digest,
        "expected_satisfiable": expected_satisfiable, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _installed_tcb() -> dict[str, str]:
    """The installed auditor's TCB, admitted only when it names the bound files."""
    installed = IndependentAuditor.tcb()
    if any(type(value) is not str or value.startswith(UNAVAILABLE_PREFIX)
           for value in installed.values()):
        raise Unavailable("installed checker cannot compute its trusted computing base")
    bound = {"specification_hash": _file_digest(_STANDARD / "VSTD-1.md"),
             "implementation_hash": _file_digest(Path(checker_module.__file__)),
             "parser_hash": _file_digest(Path(receipt_module.__file__))}
    if any(installed.get(name) != digest for name, digest in bound.items()):
        raise Unavailable("installed checker resolved files outside the bound mechanism")
    return installed


def _search_bound(n_vars: int, clauses: Sequence[Sequence[int]]) -> tuple[int, int]:
    """Distinct variables and an a priori worst-case DPLL work bound.

    At most 2**(d + 1) search nodes; each runs at most d + 1 propagation passes
    over every literal and clause, plus the final n_vars model fill.
    """
    distinct = len({abs(literal) for clause in clauses for literal in clause})
    literals = sum(len(clause) for clause in clauses)
    return distinct, (2 ** (distinct + 1) * (literals + len(clauses) + 1)
                      * (distinct + 1) + max(n_vars, 0))


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
            raise Refuted("retained replay evidence differs")
        budget = Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        _, receipt, _ = receipt_statics.check_receipt_statics(
            value["receipt_object"], value["receipt_base64"],
            subject_id=request["subject_id"], object_digest=request["object_digest"],
            max_receipt_bytes=limits["max_receipt_bytes"], budget=budget)
        evidence = receipt.evidence
        distinct, steps = _search_bound(evidence.n_vars, evidence.clauses)
        if max(evidence.n_vars, distinct) > limits["max_sat_variables"]:
            raise Unavailable("selected SAT variable bound exhausted")
        if steps > limits["max_search_steps"]:
            raise Unavailable("selected DPLL search-step bound exhausted")
        if len(evidence.atomic_reasons) > limits["max_reasons"]:
            raise Unavailable("selected atomic reason bound exhausted")
        installed = _installed_tcb()
        replayed = IndependentAuditor.audit_claim_derivation(
            claim_id=receipt.claim.id, n_vars=evidence.n_vars, clauses=evidence.clauses,
            atomic_reasons=evidence.atomic_reasons,
            expected_satisfiable=request["expected_satisfiable"],
            assumptions=evidence.assumptions).to_dict()
        if replayed["trusted_computing_base"] != installed:
            raise Unavailable("installed checker changed its trusted computing base during replay")
        retained = receipt.independent_audit.to_dict()
        for name in REPLAYED_FIELDS:
            budget.tick()
            if canonical_json_dumps(replayed[name]) != canonical_json_dumps(retained[name]):
                raise Refuted("replayed independent audit differs at " + name)
        return MechanismDecision(MechanismOutcome.PASS,
            "installed VSTD-1 auditor reproduces the retained independent audit",
            {"receipt_id": receipt.receipt_id, "distinct_variables": distinct,
             "search_step_bound": steps, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except RecursionError:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "checker recursion ceiling exhausted")
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ReceiptValidationReplayMechanism:
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
                                     "bound RECEIPT replay proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected receipt bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ReceiptValidationReplayError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ReceiptValidationReplayMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "RECEIPT", "scope": SCOPE,
        "receipt_validation_replay": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED"),
        "claim_truth": "NOT_ESTABLISHED",
        "independence_basis_replay": "NOT_ESTABLISHED",
        "target_solver_replay": "NOT_ESTABLISHED",
        "external_referent_bytes": "NOT_ESTABLISHED",
        "receipt_generation": "NOT_ESTABLISHED",
        "revocation_event_logging": "NOT_ESTABLISHED",
        "ledger_registration": "NOT_ESTABLISHED",
        "prerequisite_resolution": "NOT_ESTABLISHED",
        "hash_chain_continuity": "NOT_ESTABLISHED",
        "issuer_authenticity": "NOT_ESTABLISHED",
        "whole_receipt_dynamics": "NOT_ESTABLISHED",
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
        raise ReceiptValidationReplayError("certificate byte bound exhausted")
    return encoded


def build_receipt_validation_replay_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    """Replay one selected receipt's audit and retain its exact available evidence."""
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ReceiptValidationReplayError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ReceiptValidationReplayError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_receipt_validation_replay_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Replay exact certificate bytes against independent request and policy."""
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ReceiptValidationReplayError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ReceiptValidationReplayError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ReceiptValidationReplayError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ReceiptValidationReplayError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ReceiptValidationReplayError):
            raise
        raise ReceiptValidationReplayError(
            "invalid retained RECEIPT replay certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "PROPOSITION_DIGEST", "REPLAYED_FIELDS", "ReceiptValidationReplayDescriptor",
           "ReceiptValidationReplayError", "registration",
           "receipt_validation_replay_policy", "receipt_validation_replay_request",
           "build_receipt_validation_replay_certificate",
           "recheck_receipt_validation_replay_certificate"]
