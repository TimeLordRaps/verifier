"""Verifier Standard (VSTD) grounded claim-coordinate certification example.

JavaScript Object Notation (JSON). This executable specimen earns obligation 1.1
only. Missing obligations keep the complete profile UNKNOWN. It does not invent
evidence to turn a partial example into a conforming full profile.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verifier import (
    BoundProposition, CertificationPolicy, CertificationRequest, EvidenceBounds,
    EvidenceStore, MechanismAdmission, NativeCertificationMechanism,
    VerificationSession, build_grounded_certificate,
)
from verifier.core.certificate import ClaimBinding, ClaimCoordinate, ResourceBounds, canonical_bytes, canonical_digest
from verifier.core.grounded_certification import evidence_root
from verifier.core.kernel import reference_descriptor


def make_example() -> tuple[CertificationRequest, CertificationPolicy, VerificationSession]:
    """Create real native-checker inputs for one bounded claim-record comparison."""
    record = {
        "claim_id": "claim:grounded-example", "subject": "artifact:grounded-example",
        "statement": "The retained record states the selected bounded claim.",
        "predicate": "claim-record-binding", "scope": "one retained claim record",
        "limitations": ["Record binding does not establish the underlying computational claim."],
        "falsification_condition": "The retained record differs from the external claim coordinate.",
    }
    mechanism = NativeCertificationMechanism()
    policy = CertificationPolicy({"1.1": MechanismAdmission(
        mechanism.mechanism_id, mechanism.mechanism_digest, ("local:native-record-checker",))})
    store = EvidenceStore()
    ref = store.add(canonical_bytes(record))
    binding = ClaimBinding(record["statement"], ClaimCoordinate(record["subject"], record["predicate"],
        {"scope": record["scope"], "claim_record_digest": canonical_digest(record)}),
        policy.digest(), evidence_root([ref]), reference_descriptor(), ResourceBounds(10000, 10000, 1000000))
    proposition = BoundProposition(record["claim_id"], "vstd.obligation.1.1", True,
        mechanism.mechanism_id, mechanism.mechanism_digest, (ref,), ("local:native-record-checker",),
        EvidenceBounds(1, 1000000), {"claim_binding_digest": binding.digest(),
        "claim_binding": canonical_bytes(binding.to_dict()).decode("utf-8")})
    session = VerificationSession(store)
    session.register(mechanism)
    return CertificationRequest(record["claim_id"], binding, 1, {"1.1": proposition}), policy, session


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory for the replay specimen.")
    args = parser.parse_args()
    request, policy, session = make_example()
    certificate = build_grounded_certificate(request, policy=policy, session=session)
    refs = tuple(r for p in request.obligations.values() for r in p.evidence_refs)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in {"request.json": request.to_dict(), "policy.json": policy.to_dict(),
                        "evidence.json": session.evidence.export_base64(refs),
                        "certificate.json": certificate}.items():
        (args.output/name).write_bytes((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
    print("Obligation 1.1: PASS; complete VSTD-1 grounded certification: UNKNOWN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
