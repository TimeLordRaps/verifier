"""Verifier Standard (VSTD) grounded certification across object profiles 1–5.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Certificates carry replay inputs, never executable plugins or their own authority.
The checker supplies an external admission policy and registered mechanisms.
Byte/item bounds are enforced here; Python mechanism execution is not sandboxed
or forcibly time-limited. A policy must admit mechanisms suitable for its runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
from typing import Any, Mapping, Sequence
import re

from .certificate import ClaimBinding, canonical_bytes, canonical_digest
from .depth import claim_binding_from_dict
from .evidence import (
    BoundProposition, EvidenceBindingError, EvidenceStore, MechanismOutcome,
    VerificationMechanism, VerificationSession,
)
from .profile_obligations import (
    BY_ID, OBLIGATIONS, PROFILE_NAMES, catalog_digest, specification_digest,
)
from .receipt import strict_json_loads

REQUEST_FORMAT = "verifier-grounded-request-1"
POLICY_FORMAT = "verifier-grounded-policy-1"
CERTIFICATE_FORMAT = "verifier-grounded-certification-1"
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")


class CertificationError(ValueError):
    """Malformed, substituted, or unreplayable grounded certification input."""


def _object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CertificationError(f"{label}: expected exactly {sorted(keys)}")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CertificationError(f"{label}: nonempty string required")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CertificationError(f"{label}: integer from {minimum} to {maximum} required")
    return value


def _digest(value: Any, label: str, *, prefixed: bool = False) -> str:
    if not isinstance(value, str):
        raise CertificationError(f"{label}: digest required")
    raw = value.removeprefix("sha256:") if prefixed else value
    if not _HASH.fullmatch(raw):
        raise CertificationError(f"{label}: SHA-256 digest required")
    return "sha256:" + raw if prefixed else raw


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value):
        raise CertificationError(f"{label}: nonempty string array required")
    if value != sorted(set(value)):
        raise CertificationError(f"{label}: sorted unique strings required")
    return tuple(value)


def _snapshot(value: Any) -> Any:
    try:
        data = canonical_bytes(value)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise CertificationError("document exceeds hard byte bound")
        return strict_json_loads(data.decode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CertificationError(f"input is not bounded canonical JSON: {exc}") from exc


@dataclass(frozen=True)
class MechanismAdmission:
    """Checker-selected executable and trust roots for one exact obligation."""
    mechanism_id: str
    mechanism_digest: str
    trust_roots: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"mechanism_id": self.mechanism_id,
                "mechanism_digest": _digest(self.mechanism_digest, "mechanism", prefixed=True),
                "trust_roots": list(self.trust_roots)}

    @classmethod
    def from_dict(cls, value: Any) -> MechanismAdmission:
        value = _object(value, {"mechanism_id", "mechanism_digest", "trust_roots"}, "admission")
        return cls(_text(value["mechanism_id"], "mechanism_id"),
            _digest(value["mechanism_digest"], "mechanism_digest", prefixed=True),
            _strings(value["trust_roots"], "trust_roots"))


@dataclass(frozen=True)
class CertificationPolicy:
    """External mechanism admission and resource policy, not certificate authority.

    Item counts are dimensionless; byte ceilings count decoded evidence bytes or
    canonical certificate bytes. Policy admission does not prove mechanism correctness.
    """
    admissions: Mapping[str, MechanismAdmission]
    max_evidence_items: int = 512
    max_evidence_bytes: int = 8 * 1024 * 1024
    max_certificate_bytes: int = 16 * 1024 * 1024
    catalog: str = field(default_factory=catalog_digest)
    specification: str = field(default_factory=specification_digest)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": POLICY_FORMAT,
                "admissions": {k: v.to_dict() for k, v in sorted(self.admissions.items())},
                "max_evidence_items": self.max_evidence_items,
                "max_evidence_bytes": self.max_evidence_bytes,
                "max_certificate_bytes": self.max_certificate_bytes,
                "catalog_digest": self.catalog, "specification_digest": self.specification}

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> CertificationPolicy:
        value = _object(value, {"schema_version", "admissions", "max_evidence_items",
            "max_evidence_bytes", "max_certificate_bytes", "catalog_digest", "specification_digest"}, "policy")
        if value["schema_version"] != POLICY_FORMAT:
            raise CertificationError("unsupported policy version")
        admissions = value["admissions"]
        if not isinstance(admissions, dict) or set(admissions) - set(BY_ID):
            raise CertificationError("policy contains unknown obligation coordinates")
        return cls({k: MechanismAdmission.from_dict(v) for k, v in admissions.items()},
            _integer(value["max_evidence_items"], "max_evidence_items", 0, 4096),
            _integer(value["max_evidence_bytes"], "max_evidence_bytes", 0, MAX_DOCUMENT_BYTES),
            _integer(value["max_certificate_bytes"], "max_certificate_bytes", 1, MAX_DOCUMENT_BYTES),
            _digest(value["catalog_digest"], "catalog_digest"),
            _digest(value["specification_digest"], "specification_digest"))


def _bound_proposition(value: Any) -> BoundProposition:
    value = _object(value, {"subject_id", "predicate", "expected", "mechanism_id",
        "mechanism_digest", "evidence_refs", "trust_roots", "bounds", "parameters"}, "obligation binding")
    for name in ("subject_id", "predicate", "mechanism_id"):
        _text(value[name], name)
    _digest(value["mechanism_digest"], "mechanism_digest", prefixed=True)
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not refs or len(refs) > 4096:
        raise CertificationError("evidence_refs: nonempty bounded array required")
    for ref in refs:
        _digest(ref, "evidence reference", prefixed=True)
    _strings(value["trust_roots"], "trust_roots")
    bounds = _object(value["bounds"], {"max_evidence_items", "max_evidence_bytes"}, "evidence bounds")
    _integer(bounds["max_evidence_items"], "max_evidence_items", 0, 4096)
    _integer(bounds["max_evidence_bytes"], "max_evidence_bytes", 0, MAX_DOCUMENT_BYTES)
    if not isinstance(value["parameters"], dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in value["parameters"].items()
    ):
        raise CertificationError("parameters must map strings to strings")
    try:
        result = BoundProposition.from_dict(value)
        if canonical_bytes(result.to_dict()) != canonical_bytes(value):
            raise CertificationError("noncanonical obligation binding")
        return result
    except (ValueError, TypeError, KeyError) as exc:
        raise CertificationError(str(exc)) from exc


def _claim_binding(value: Any) -> ClaimBinding:
    value = _object(value, {"claim", "coordinate", "policy_root", "evidence_root",
        "verifier", "bounds", "prior_commitment"}, "claim binding")
    _text(value["claim"], "claim")
    coord = _object(value["coordinate"], {"subject", "predicate", "parameters"}, "coordinate")
    _text(coord["subject"], "subject")
    _text(coord["predicate"], "predicate")
    _digest(value["policy_root"], "policy_root")
    _digest(value["evidence_root"], "evidence_root")
    bounds = _object(value["bounds"], {"verification_cost_bound", "memory_bound",
                                     "certificate_size_bound"}, "claim bounds")
    for k, v in bounds.items():
        _integer(v, k, 0, 2**53-1)
    try:
        result = claim_binding_from_dict(value)
        if canonical_bytes(result.to_dict()) != canonical_bytes(value):
            raise CertificationError("claim binding must round trip without coercion")
        return result
    except (ValueError, TypeError, KeyError) as exc:
        raise CertificationError(str(exc)) from exc


@dataclass(frozen=True)
class CertificationRequest:
    """Exact claim and individual evidence propositions; no supplied outcomes."""
    claim_id: str
    binding: ClaimBinding
    target_profile: int
    obligations: Mapping[str, BoundProposition]

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": REQUEST_FORMAT, "claim_id": self.claim_id,
                "binding": self.binding.to_dict(), "target_profile": self.target_profile,
                "obligations": {k: v.to_dict() for k, v in sorted(self.obligations.items())}}

    @classmethod
    def from_dict(cls, value: Any) -> CertificationRequest:
        value = _object(value, {"schema_version", "claim_id", "binding", "target_profile", "obligations"}, "request")
        if value["schema_version"] != REQUEST_FORMAT:
            raise CertificationError("unsupported request version")
        target = _integer(value["target_profile"], "target_profile", 1, 5)
        obligations = value["obligations"]
        if not isinstance(obligations, dict) or any(
            k not in BY_ID or BY_ID[k].profile > target for k in obligations
        ):
            raise CertificationError("request contains unknown or out-of-target obligations")
        return cls(_text(value["claim_id"], "claim_id"), _claim_binding(value["binding"]),
            target, {k: _bound_proposition(v) for k, v in obligations.items()})


def evidence_root(references: Sequence[str]) -> str:
    """Commit to the sorted set of exact evidence addresses, not their truth."""
    return canonical_digest(sorted({_digest(r, "evidence reference", prefixed=True) for r in references}))


def certification_checker_digest() -> str:
    """Bind orchestration and its local parser/evidence dependencies to exact bytes."""
    names = ("grounded_certification.py", "profile_obligations.py", "evidence.py",
             "certificate.py", "depth.py", "receipt.py", "kernel.py", "grounding.py")
    root = Path(__file__).parent
    return canonical_digest({name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                             for name in names})


def _prepare(request: CertificationRequest, policy: CertificationPolicy) -> tuple[CertificationRequest, CertificationPolicy]:
    request = CertificationRequest.from_dict(_snapshot(request.to_dict()))
    policy = CertificationPolicy.from_dict(_snapshot(policy.to_dict()))
    if policy.catalog != catalog_digest() or policy.specification != specification_digest():
        raise CertificationError("policy catalogue or specification coordinate is not current")
    if request.binding.policy_root != policy.digest():
        raise CertificationError("claim is not bound to the externally supplied policy")
    refs = tuple(r for b in request.obligations.values() for r in b.evidence_refs)
    if request.binding.evidence_root != evidence_root(refs):
        raise CertificationError("claim evidence root does not bind these obligation inputs")
    return request, policy


def _assess(request: CertificationRequest, policy: CertificationPolicy, session: VerificationSession) -> dict[str, Any]:
    selected = [o for o in OBLIGATIONS if o.profile <= request.target_profile]
    refs = sorted({r for b in request.obligations.values() for r in b.evidence_refs})
    global_problem = ""
    if len(refs) > policy.max_evidence_items:
        global_problem = "global evidence item bound exceeded"
    else:
        total_bytes = 0
        for ref in refs:
            try:
                total_bytes += len(session.evidence.resolve(ref))
            except EvidenceBindingError:
                continue  # The exact affected obligation retains UNKNOWN below.
            if total_bytes > policy.max_evidence_bytes:
                global_problem = "global evidence byte bound exceeded"
                break
    results: dict[str, Any] = {}
    for obligation in selected:
        prop = request.obligations.get(obligation.id)
        admission = policy.admissions.get(obligation.id)
        reason = global_problem
        evaluation = None
        if not reason:
            if prop is None:
                reason = "required obligation evidence is missing"
            elif admission is None:
                reason = "external policy admits no mechanism for this obligation"
            elif prop.subject_id != request.claim_id or prop.predicate != obligation.predicate or prop.expected is not True:
                reason = "proposition does not bind the exact claim, obligation and Boolean true"
            elif prop.parameters.get("claim_binding_digest") != request.binding.digest():
                reason = "proposition does not bind the exact claim commitment"
            elif (prop.mechanism_id != admission.mechanism_id
                  or _digest(prop.mechanism_digest, "mechanism", prefixed=True) != admission.mechanism_digest
                  or prop.trust_roots != admission.trust_roots):
                reason = "mechanism or trust roots are not admitted by the external policy"
            else:
                evaluated = session.evaluate(prop)
                if type(evaluated.outcome) is not MechanismOutcome:
                    reason = "mechanism returned an invalid outcome type"
                else:
                    try:
                        evaluation = _snapshot(evaluated.to_dict())
                    except CertificationError:
                        reason = "mechanism observations are not bounded canonical data"
        outcome = "UNKNOWN" if evaluation is None else evaluation["outcome"]
        blocked = [d for d in obligation.depends_on if not results[d]["established"]]
        results[obligation.id] = {
            "outcome": outcome, "established": outcome == "PASS" and not blocked,
            "blocked_by": blocked, "reason": reason or evaluation["details"],
            "evaluation": evaluation,
        }
    profiles: dict[str, Any] = {}
    depth = 0
    for profile in range(1, request.target_profile + 1):
        ids = [o.id for o in selected if o.profile == profile]
        direct = all(results[k]["established"] for k in ids)
        prefix = 0
        for k in ids:
            if not results[k]["established"]:
                break
            prefix += 1
        cumulative = direct and depth == profile-1
        if cumulative:
            depth = profile
        profiles[str(profile)] = {
            "name": PROFILE_NAMES[profile], "obligation_count": len(ids),
            "established_prefix": prefix, "coordinate_established": direct,
            "cumulative_established": cumulative,
            "blocking_obligations": [k for k in ids if not results[k]["established"]],
            "missing_prerequisite_profiles": [p for p in range(1, profile)
                if not profiles[str(p)]["cumulative_established"]],
        }
    failed = [k for k, v in results.items() if v["outcome"] == "FAIL"]
    complete = depth == request.target_profile
    return {"status": "FAIL" if failed else "PASS" if complete else "UNKNOWN",
            "certification_status": "ESTABLISHED" if complete else "NOT_ESTABLISHED",
            "certified_profile_depth": depth, "failed_obligations": failed,
            "profiles": profiles, "obligations": results}


def assess_grounded_certification(request: CertificationRequest, *, policy: CertificationPolicy,
                                 session: VerificationSession) -> dict[str, Any]:
    """Execute each admitted obligation and derive cumulative certification.

    FAIL refutes a required obligation under the admitted mechanism; UNKNOWN
    identifies absent or unevaluable support. Neither is a universal claim about
    the subject. Positive results remain relative to the supplied trusted policy.
    """
    request, policy = _prepare(request, policy)
    return _assess(request, policy, session)


def build_grounded_certificate(request: CertificationRequest, *, policy: CertificationPolicy,
                               session: VerificationSession) -> dict[str, Any]:
    """Build a fresh portable certificate by executing, never accepting a result."""
    request, policy = _prepare(request, policy)
    refs = sorted({r for p in request.obligations.values() for r in p.evidence_refs})
    if len(refs) > policy.max_evidence_items:
        raise CertificationError("cannot embed evidence exceeding the policy item bound")
    available = [r for r in refs if r in session.evidence]
    if sum(len(session.evidence.resolve(r)) for r in available) > policy.max_evidence_bytes:
        raise CertificationError("cannot embed evidence exceeding the policy byte bound")
    # Freeze the evidence store before execution, including explicit missing refs.
    payloads = session.evidence.export_base64(available)
    store = EvidenceStore()
    store.import_base64(payloads)
    replay = VerificationSession(store)
    # Mechanisms are caller-owned capabilities; no code is loaded from a receipt.
    for mechanism in session.registered_mechanisms():
        replay.register(mechanism)
    result = _assess(request, policy, replay)
    certificate = {"schema_version": CERTIFICATE_FORMAT,
        "checker_digest": certification_checker_digest(),
        "catalog_digest": policy.catalog, "specification_digest": policy.specification,
        "policy_digest": policy.digest(), "request": request.to_dict(),
        "evidence_payloads": payloads, "result": result}
    certificate["digest"] = canonical_digest(certificate)
    ceiling = min(policy.max_certificate_bytes,
                  request.binding.bounds.certificate_size_bound or MAX_DOCUMENT_BYTES)
    if len(canonical_bytes(certificate)) > ceiling:
        raise CertificationError("certificate byte bound exceeded")
    return _snapshot(certificate)


def recheck_grounded_certificate(certificate: Mapping[str, Any], *, policy: CertificationPolicy,
                                 mechanisms: Sequence[VerificationMechanism],
                                 expected_request_digest: str) -> dict[str, Any]:
    """Rehash and rerun under an external policy; reject a changed carried result."""
    certificate = _snapshot(certificate)
    _object(certificate, {"schema_version", "catalog_digest", "specification_digest",
        "policy_digest", "checker_digest", "request", "evidence_payloads", "result", "digest"}, "certificate")
    if certificate["schema_version"] != CERTIFICATE_FORMAT:
        raise CertificationError("unsupported grounded certificate version")
    observed_digest = canonical_digest({k: v for k, v in certificate.items() if k != "digest"})
    if certificate["digest"] != observed_digest:
        raise CertificationError("certificate digest does not match bytes")
    request = CertificationRequest.from_dict(certificate["request"])
    if canonical_digest(request.to_dict()) != _digest(expected_request_digest, "expected_request_digest"):
        raise CertificationError("certificate does not bind the externally expected request")
    if certificate["checker_digest"] != certification_checker_digest():
        raise CertificationError("certificate checker implementation coordinate changed")
    request, policy = _prepare(request, policy)
    if (certificate["catalog_digest"] != policy.catalog
        or certificate["specification_digest"] != policy.specification
        or certificate["policy_digest"] != policy.digest()):
        raise CertificationError("certificate catalogue, specification or policy was substituted")
    ceiling = min(policy.max_certificate_bytes,
                  request.binding.bounds.certificate_size_bound or MAX_DOCUMENT_BYTES)
    if len(canonical_bytes(certificate)) > ceiling:
        raise CertificationError("certificate byte bound exceeded")
    payloads = certificate["evidence_payloads"]
    refs = {r for p in request.obligations.values() for r in p.evidence_refs}
    if not isinstance(payloads, dict) or set(payloads) - refs:
        raise CertificationError("unreferenced or invalid embedded evidence")
    if any(not isinstance(v, str) for v in payloads.values()):
        raise CertificationError("evidence payloads must be base64 strings")
    store = EvidenceStore()
    try:
        store.import_base64(payloads)
    except EvidenceBindingError as exc:
        raise CertificationError(str(exc)) from exc
    session = VerificationSession(store)
    try:
        for mechanism in mechanisms:
            session.register(mechanism)
    except EvidenceBindingError as exc:
        raise CertificationError(str(exc)) from exc
    observed = _assess(request, policy, session)
    if canonical_bytes(observed) != canonical_bytes(certificate["result"]):
        raise CertificationError("recomputed result differs from the certificate")
    return observed
