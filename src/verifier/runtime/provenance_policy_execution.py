"""Source-bound provenance POLICY checks for Verifier Standard (VSTD).

These propositions concern the actual installed decision engine on recorded
graph facts. They do not establish those facts, license authority, enforcement
by downstream applications or complete kind conformance. Unsupported variants
remain UNKNOWN. The parent rechecks control certificates through the independent kernel.
Terminology: conjunctive normal form (CNF); grounded decision certificate (GDC).
"""
from __future__ import annotations

from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-provenance-policy-1"
SEMANTIC_VERSION = "verifier-provenance-policy-obligations-1"
IMPLEMENTATION = "src/verifier/data/policy.py"
WORKER = "provenance_policy_worker.py"
REQUEST_SCHEMA = "verifier-provenance-policy-request-1"
OBSERVATION_SCHEMA = "verifier-provenance-policy-observations-1"
BOUNDARY = ("Fresh finite executions of the exact owned provenance-policy implementation on synthetic recorded graphs. "
            "Not provenance truth, license validity or authority, downstream enforcement, full kind conformance or package polish.")
_CONTRACTS = (
    ("POLICY-1.1", "provenance-input-scope", 1,
     "A decision must identify its selected target and rule; an absent target cannot supply evidence of compliance.",
     "All three policies retain exact target/rule identities and return INDETERMINATE for an unrecorded target."),
    ("POLICY-1.2", "provenance-rule-defaults", 1,
     "No-revoked and all-valid are different rules; unknown or challenged metadata must not silently mean explicitly valid.",
     "All 36 pairs of the six recorded status classes obey their distinct predicates; an unrelated revoked artifact does not enter the selected lineage."),
    ("POLICY-2.1", "provenance-decision-encoding", 2,
     "A reported decision must encode every selected lineage member, not just return the expected status word.",
     "Each status-pair execution emits the exact target assertion, member dependencies and positive or negative facts with the corresponding variable map."),
    ("POLICY-2.2", "license-selection", 2,
     "An explicit allowed-license selection must govern the decision without falling back to defaults or unrelated artifact metadata.",
     "Seven executions distinguish default/custom/empty license selections, missing rights, disallowed roots and a non-root target's different license."),
    ("POLICY-3.1", "incomplete-lineage", 3,
     "Missing graph members or missing root-source evidence must not produce a vacuous successful policy decision.",
     "Every policy refuses a dangling lineage; a rootless cycle is INDETERMINATE for source-license approval."),
    ("POLICY-3.2", "encoding-contradiction", 3,
     "Disagreement among rule computation, solver and grounded encoding must be exposed rather than selecting whichever result passes.",
     "Passing and refuting controls retain kernel-checkable bound certificates; contradictory solver/direct inputs refuse, and four underbound or duplicated encodings cannot certify."),
)
_STATUSES = ("VALID", "CHALLENGED", "STALE", "SUPERSEDED", "REVOKED", "UNKNOWN")
_IDS = {"no_revoked": "POL-NO-REVOKED-ANCESTORS", "all_valid": "POL-ALL-ANCESTORS-VALID",
        "licenses": "POL-APPROVED-LICENSES"}


def catalog() -> list[dict[str, Any]]:
    return [{"coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
             "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": "POLICY",
             "tier": tier, "reason": reason, "exact_claim": claim, "semantic_version": SEMANTIC_VERSION,
             "proposition_digest": value_digest({"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
             "checking_mechanism": "verifier.runtime.provenance_policy_execution.evaluate",
             "scope": "fresh_provenance_policy_" + slug.replace("-", "_"), "adapter": ADAPTER}
            for coordinate, slug, tier, reason, claim in _CONTRACTS]


def _decision(row: dict[str, Any], name: str, target: str, expected: bool | None) -> bool:
    return (row["policy_id"] == _IDS[name] and row["target_artifact_id"] == target
            and row["passed"] is (expected is True)
            and row["verdict"] == ("INDETERMINATE" if expected is None else "VERIFIED" if expected else "FALSIFIED"))


def _matrix(observed: dict[str, Any]) -> bool:
    return (observed["status_values"] == list(_STATUSES)
            and [(row["root"], row["target"]) for row in observed["matrix"]]
                == [(root, target) for root in _STATUSES for target in _STATUSES])


def _certificate(value: Any, passed: bool) -> bool:
    from verifier.core.certificate import (certificate_from_dict, canonical_digest,
        ClaimBinding, ClaimCoordinate, ResourceBounds)
    from verifier.core.kernel import check, reference_descriptor
    clauses = [[-1, 2], [2 if passed else -2], [1]]
    binding = ClaimBinding("POL-CONTROL", ClaimCoordinate("target", "POL-CONTROL"),
        canonical_digest(clauses), canonical_digest(["POL-CONTROL", "target"]), reference_descriptor(),
        ResourceBounds(verification_cost_bound=7, memory_bound=3, certificate_size_bound=0))
    try:
        certificate = certificate_from_dict(value)
        return (sorted(certificate.formula) == sorted(tuple(row) for row in clauses)
                and certificate.header.verdict.value == ("PASS" if passed else "FAIL")
                and check(certificate, binding=binding, budget=1000).accepted)
    except (ValueError, TypeError, KeyError):
        return False


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Independent finite truth table and formula oracle, not subject reuse."""
    rows = observed["matrix"]
    if coordinate == "POLICY-1.1":
        return (_matrix(observed) and set(observed["missing"]) == set(_IDS)
                and all(_decision(observed["missing"][name], name, "absent", None) for name in _IDS)
                and all(row[name]["target_artifact_id"] == "target" and row[name]["policy_id"] == _IDS[name]
                        for row in rows for name in ("no_revoked", "all_valid")))
    if coordinate == "POLICY-1.2":
        return (_matrix(observed) and all(
            _decision(row["no_revoked"], "no_revoked", "target", "REVOKED" not in (row["root"], row["target"]))
            and _decision(row["all_valid"], "all_valid", "target", row["root"] == row["target"] == "VALID") for row in rows))
    if coordinate == "POLICY-2.1":
        if not _matrix(observed):
            return False
        for row in rows:
            for name, prefix in (("no_revoked", "CLEAN"), ("all_valid", "VALID")):
                clauses = []
                mapping = {"TARGET_ADMISSIBLE": 1}
                for index, member in enumerate(("root", "target"), 2):
                    good = row[member] != "REVOKED" if name == "no_revoked" else row[member] == "VALID"
                    mapping[prefix + "_" + member] = index
                    clauses.extend(([-1, index], [index if good else -index]))
                if canonical_bytes([row[name]["clauses"], row[name]["variable_map"]]) != canonical_bytes([clauses + [[1]], mapping]):
                    return False
        return True
    if coordinate == "POLICY-2.2":
        expected = [("MIT", None, "MIT", True), ("PROPRIETARY", None, "MIT", False),
                    (None, None, "MIT", False), ("PROPRIETARY", ["PROPRIETARY"], "MIT", True),
                    ("MIT", [], "MIT", False), ("MIT", ["Apache-2.0"], "MIT", False),
                    ("MIT", None, "PROPRIETARY", True)]
        return (len(observed["licenses"]) == len(expected) and all(
            (row["license"], row["allowed"], row["target_license"]) == fields[:3]
            and _decision(row["result"], "licenses", "target", fields[3])
            for row, fields in zip(observed["licenses"], expected)))
    if coordinate == "POLICY-3.1":
        return (set(observed["invalid"]) == set(_IDS)
                and all(canonical_bytes(row) == canonical_bytes({"returned": False, "exception": "PolicyEncodingError"})
                        for row in observed["invalid"].values())
                and _decision(observed["cycle"], "licenses", "target", None))
    if coordinate == "POLICY-3.2":
        controls = observed["controls"]
        for name, passed in (("pass", True), ("fail", False), ("direct-conflict", False), ("solver-conflict", False)):
            row = controls[name]
            returned = name in {"pass", "fail"}
            if (row["returned"] is not returned or row["passed"] is not (passed if returned else None)
                    or row["exception"] != (None if returned else "PolicyEncodingError")
                    or not _certificate(row["certificate"], passed)):
                return False
        return all(canonical_bytes(controls[name]) == canonical_bytes(
                       {"returned": False, "exception": "PolicyEncodingError", "passed": None, "certificate": None})
                   for name in ("missing-fact", "missing-dependency", "missing-target", "duplicate-fact"))
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound
    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected
    return evaluate_selected(snapshot, item, route)
