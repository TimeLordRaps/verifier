"""Experimental Verifier Standard (VSTD) finite formation session adapter.

Secure Hash Algorithm 256-bit (SHA-256) digests bind exact input bytes. A PASS
means only that the named finite formation certificate checks under its declared
context. Ground and authority axiom agency roots are assumption labels, not
proofs of grounding or authority. All source-level residual obligations remain.

The mechanism coordinate hashes a canonical inventory of four fixed sibling
source files and the compiled rule profile. This is selected source-file identity,
not loaded-code, full dependency, execution provenance or independent attestation.
Only that local identity calculation reads files, at module import. Evaluation
does not read files, execute uploaded code, import a producer or promote silo
statuses. Finite checker budgets are not a general process sandbox.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core.evidence import (
    BoundProposition,
    EvidenceBounds,
    MechanismDecision,
    MechanismOutcome,
)

from .formation_checker import check_formation
from .formation_wire import (
    FormationError,
    MAX_RECORD_BYTES,
    RESIDUAL_OBLIGATIONS,
    canonical_bytes,
    decode_subject,
    digest_bytes,
    profile_digest,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PARAMETERS = frozenset({
    "profile_digest", "ground_artifact_digest", "authority_axiom_agency_digest",
})
_PROFILE_DIGEST = profile_digest()
_SOURCE_NAMES = (
    "formation_mechanism.py", "formation_checker.py", "formation_wire.py", "network.py",
)


def _implementation_digest() -> str:
    root = Path(__file__).parent
    inventory = {
        "schema_version": "VSTD-TYPED-FORMATION-SOURCE-IDENTITY-0.1",
        "profile_digest": _PROFILE_DIGEST,
        "sources": [
            {"path": name, "digest": digest_bytes((root / name).read_bytes())}
            for name in _SOURCE_NAMES
        ],
    }
    return digest_bytes(canonical_bytes(inventory))


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _decision(
    outcome: MechanismOutcome, status: str, reason: str,
    report: dict[str, Any] | None = None,
) -> MechanismDecision:
    return MechanismDecision(
        outcome=outcome,
        details=reason,
        observations={
            "status": status,
            "reason_codes": [reason] if reason else [],
            "formation_report": report,
            "residual_obligations": list(RESIDUAL_OBLIGATIONS),
            "trust_roots_meaning": "DECLARED_ASSUMPTIONS_ONLY",
            "claim_scope": "EXACT_FINITE_FORMATION_CERTIFICATE_ONLY",
        },
    )


class FormationPathCertificateMechanism:
    """Recheck two immutable records under one exact experimental proposition."""

    mechanism_id = "vstd.typed_formation.checked.0.1"
    mechanism_digest = _implementation_digest()

    def evaluate(
        self, binding: BoundProposition, evidence: Sequence[bytes]
    ) -> MechanismDecision:
        """Apply strict native bindings even when invoked without a session.

        The session itself can refuse unavailable evidence before invoking this
        adapter. Such a session refusal has no formation report because no
        formation check ran. Direct preflight refusals likewise carry no report.
        """

        unknown = MechanismOutcome.UNKNOWN
        fail = MechanismOutcome.FAIL
        if type(binding) is not BoundProposition:
            return _decision(unknown, "UNKNOWN", "FORMATION_BINDING_UNSUPPORTED")
        if (
            type(binding.mechanism_id) is not str or binding.mechanism_id != self.mechanism_id
            or not _is_digest(binding.mechanism_digest)
            or binding.mechanism_digest != self.mechanism_digest
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_IMPLEMENTATION_UNSUPPORTED")
        if (
            type(binding.predicate) is not str or binding.predicate != self.mechanism_id
            or type(binding.expected) is not str or binding.expected != "CHECKED"
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_PREDICATE_UNSUPPORTED")
        parameters = binding.parameters
        if type(parameters) is not dict:
            return _decision(unknown, "UNKNOWN", "FORMATION_PARAMETERS_UNSUPPORTED")
        parameters = dict(parameters)
        if (
            len(parameters) != len(_PARAMETERS)
            or any(type(key) is not str for key in parameters) or set(parameters) != _PARAMETERS
            or any(not _is_digest(value) for value in parameters.values())
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_PARAMETERS_UNSUPPORTED")
        if parameters["profile_digest"] != _PROFILE_DIGEST:
            return _decision(unknown, "UNKNOWN", "FORMATION_PROFILE_UNSUPPORTED")
        expected_roots = tuple(sorted(set(parameters.values())))
        if (
            type(binding.trust_roots) is not tuple or binding.trust_roots != expected_roots
            or any(not _is_digest(root) for root in binding.trust_roots)
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_ROOTS_UNSUPPORTED")
        bounds = binding.bounds
        if (
            type(bounds) is not EvidenceBounds
            or type(bounds.max_evidence_items) is not int or bounds.max_evidence_items != 2
            or type(bounds.max_evidence_bytes) is not int
            or not 0 <= bounds.max_evidence_bytes <= 2 * MAX_RECORD_BYTES
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_BOUNDS_UNSUPPORTED")
        refs = binding.evidence_refs
        if (
            type(refs) is not tuple or len(refs) != 2
            or any(not _is_digest(ref) for ref in refs) or refs[0] == refs[1]
            or not _is_digest(binding.subject_id)
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_REFERENCES_UNSUPPORTED")
        if binding.subject_id != refs[0]:
            return _decision(fail, "INVALID", "FORMATION_SUBJECT_BINDING_INVALID")
        if type(evidence) not in (tuple, list) or len(evidence) != 2:
            return _decision(unknown, "UNKNOWN", "FORMATION_EVIDENCE_UNAVAILABLE")
        subject, certificate = evidence
        if type(subject) is not bytes or type(certificate) is not bytes:
            return _decision(fail, "INVALID", "FORMATION_EVIDENCE_TYPE_INVALID")
        if (
            len(subject) > MAX_RECORD_BYTES or len(certificate) > MAX_RECORD_BYTES
            or len(subject) + len(certificate) > bounds.max_evidence_bytes
        ):
            return _decision(unknown, "UNKNOWN", "FORMATION_LIMIT_EXCEEDED")
        if (digest_bytes(subject), digest_bytes(certificate)) != refs:
            return _decision(fail, "INVALID", "FORMATION_EVIDENCE_BINDING_INVALID")
        try:
            try:
                subject_record = decode_subject(subject)
            except FormationError:
                # The pure checker reports canonical, unsupported and bounded
                # decoding failures without treating them as missing evidence.
                subject_record = None
            if subject_record is not None and subject_record["profile_digest"] == _PROFILE_DIGEST:
                context = subject_record["context"]
                if any(context[key] != parameters[key] for key in (
                    "ground_artifact_digest", "authority_axiom_agency_digest",
                )):
                    return _decision(fail, "INVALID", "FORMATION_CONTEXT_BINDING_INVALID")
            report = check_formation(subject, certificate)
            if report["status"] == "UNKNOWN":
                return _decision(unknown, "UNKNOWN", "FORMATION_CHECK_UNKNOWN", report)
            if report["status"] == "INVALID":
                return _decision(fail, "INVALID", "FORMATION_CHECK_INVALID", report)
            if report["status"] != "CHECKED":
                return _decision(unknown, "UNKNOWN", "FORMATION_CHECK_RESULT_UNSUPPORTED", report)
        except Exception:
            return _decision(unknown, "UNKNOWN", "FORMATION_EXECUTION_UNKNOWN")
        return _decision(MechanismOutcome.PASS, "CHECKED", "", report)
