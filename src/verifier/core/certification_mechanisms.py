"""Verifier Standard (VSTD) bounded native certification mechanisms.

JavaScript Object Notation (JSON); grounded decision certificate (GDC);
Secure Hash Algorithm 256-bit (SHA-256).

These adapters execute existing checkers for specifically supported obligations.
They do not certify all 47 obligations or infer physical facts from declarations.
Other obligations require separately qualified, policy-admitted domain mechanisms.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

from .certificate import canonical_bytes, canonical_digest, certificate_from_canonical_bytes
from .evidence import BoundProposition, MechanismDecision, MechanismOutcome
from .geometry_io import load_verification_geometry
from .grounded_certification import _claim_binding, _object
from .kernel import KernelOutcome, check
from .receipt import strict_json_loads


class NativeCertificationMechanism:
    """Execute bounded claim-record, geometry and decision-certificate checks."""

    mechanism_id = "vstd.grounded.native-obligations.v1"
    supported_obligations = ("1.1", "2.1", "2.2", "4.1", "4.3", "4.5")

    @property
    def mechanism_digest(self) -> str:
        names = ("certification_mechanisms.py", "grounded_certification.py", "geometry.py",
                 "geometry_io.py", "kernel.py", "grounding.py", "certificate.py",
                 "depth.py", "receipt.py", "evidence.py")
        root = Path(__file__).parent
        return "sha256:" + canonical_digest({n: hashlib.sha256((root/n).read_bytes()).hexdigest()
                                             for n in names})

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        prefix = "vstd4.rung." if binding.predicate.startswith("vstd4.rung.") else "vstd.obligation."
        obligation = binding.predicate.removeprefix(prefix)
        if obligation not in self.supported_obligations or binding.expected is not True:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "native checker does not implement this obligation")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one exact native record is required")
        try:
            outer = _claim_binding(strict_json_loads(binding.parameters["claim_binding"]))
            if outer.digest() != binding.parameters["claim_binding_digest"]:
                return MechanismDecision(MechanismOutcome.FAIL, "native input claim commitment mismatch")
            value = strict_json_loads(evidence[0].decode("utf-8"))
            if obligation == "1.1":
                value = _object(value, {"claim_id", "subject", "statement", "predicate",
                    "scope", "limitations", "falsification_condition"}, "claim record")
                valid = (
                    value["claim_id"] == binding.subject_id
                    and value["subject"] == outer.coordinate.subject
                    and value["predicate"] == outer.coordinate.predicate
                    and value["statement"] == outer.claim
                    and value["scope"] == outer.coordinate.parameters.get("scope")
                    and all(isinstance(value[k], str) and value[k].strip()
                            for k in value if k != "limitations")
                    and isinstance(value["limitations"], list)
                    and all(isinstance(x, str) and x.strip() for x in value["limitations"])
                    and canonical_digest(value) == outer.coordinate.parameters.get("claim_record_digest")
                )
                return MechanismDecision(MechanismOutcome.PASS if valid else MechanismOutcome.FAIL,
                    "exact claim-record coordinate, scope, limitations and falsifier comparison")
            if obligation in ("2.1", "2.2"):
                geometry = load_verification_geometry(value)
                if (geometry.primary_subject_id != outer.coordinate.subject
                    or geometry.canonical_digest() != outer.coordinate.parameters.get("geometry_digest")):
                    return MechanismDecision(MechanismOutcome.FAIL, "geometry does not match the exact subject and surface commitment")
                if obligation == "2.1" and (not geometry.surface.coordinate_ids
                    or not geometry.surface.scope_statement.strip()):
                    return MechanismDecision(MechanismOutcome.UNKNOWN, "an explicit nonempty selected surface and scope are required")
                return MechanismDecision(MechanismOutcome.PASS,
                    "bound geometry subject, surface and internal references checked; judgments were not promoted")
            value = _object(value, {"binding", "certificate"}, "decision evidence")
            decision_binding = _claim_binding(value["binding"])
            if (decision_binding.digest() != outer.coordinate.parameters.get("decision_binding_digest")
                or decision_binding.coordinate.subject != outer.coordinate.subject):
                return MechanismDecision(MechanismOutcome.FAIL, "decision evidence is for another bound subject or proposition")
            certificate = certificate_from_canonical_bytes(canonical_bytes(value["certificate"]))
            if obligation == "4.5" and not all(v > 0 for v in decision_binding.bounds.to_dict().values()):
                return MechanismDecision(MechanismOutcome.UNKNOWN, "positive cost, memory and size ceilings are required")
            result = check(certificate, binding=decision_binding)
            outcome = {KernelOutcome.ACCEPTED: MechanismOutcome.PASS,
                       KernelOutcome.REJECTED: MechanismOutcome.FAIL,
                       KernelOutcome.REFUSED: MechanismOutcome.UNKNOWN}[result.outcome]
            return MechanismDecision(outcome, f"native certificate checker: {result.details}",
                {"kernel_outcome": result.outcome.value,
                 "decision_verdict": None if result.verdict is None else result.verdict.value})
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, f"invalid native evidence: {exc}")
