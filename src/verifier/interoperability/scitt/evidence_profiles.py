"""Terminology: Supply Chain Integrity, Transparency, and Trust (SCITT);
Verifier Standard (VSTD).

Loss-preserving adapters for pinned experimental SCITT evidence drafts.

This module is intentionally non-normative.  It consumes only the result
vocabularies defined by the pinned individual Internet-Drafts below; it does
not implement their complete graph, disclosure, or reconciliation protocols.
Most importantly, every SCITT-derived result retains
``computational_verdict=NOT_EVALUATED``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .adapter import InteropError


COMPOSITE_DRAFT = "draft-nobuo-scitt-composite-evidence-verification-00"
DISCLOSURE_DRAFT = "draft-dogru-scitt-disclosure-evidence-07"
COMPUTATIONAL_NOT_EVALUATED = "NOT_EVALUATED"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class CompositeResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"
    MISSING = "missing"
    STALE = "stale"
    CONFLICT = "conflict"
    NOT_APPLICABLE = "not-applicable"


class UnknownReason(str, Enum):
    UNAVAILABLE_EVIDENCE = "UNAVAILABLE_EVIDENCE"
    UNSUPPORTED_VERIFIER = "UNSUPPORTED_VERIFIER"
    UNDECIDED = "UNDECIDED"


class EvidenceCondition(str, Enum):
    PROFILE_SATISFIED = "PROFILE_SATISFIED"
    PROFILE_FAILED = "PROFILE_FAILED"
    WARNING = "WARNING"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPLETE = "INCOMPLETE"
    STALE = "STALE"
    CONFLICTED = "CONFLICTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED_VERIFIER = "UNSUPPORTED_VERIFIER"
    BOUNDED_NOT_ESTABLISHED = "BOUNDED_NOT_ESTABLISHED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    EXPLICITLY_FALSIFIED = "EXPLICITLY_FALSIFIED"
    ISSUER_ASSERTED = "ISSUER_ASSERTED"
    RECONCILIATION_NO_EXCEPTIONS = "RECONCILIATION_NO_EXCEPTIONS"
    RECONCILIATION_EXCEPTIONS = "RECONCILIATION_EXCEPTIONS"
    INVALID_WINDOW = "INVALID_WINDOW"


@dataclass(frozen=True)
class BoundedEvidenceResult:
    source_document: str
    source_result: str
    evidence_condition: EvidenceCondition
    computational_verdict: str
    reason: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_document": self.source_document,
            "source_result": self.source_result,
            "evidence_condition": self.evidence_condition.value,
            "computational_verdict": self.computational_verdict,
            "reason": self.reason,
            "limitations": list(self.limitations),
        }


def consume_composite_result(
    result: str,
    *,
    unknown_reason: UnknownReason | None = None,
) -> BoundedEvidenceResult:
    """Preserve the composite result code without treating profile pass as truth."""

    try:
        code = CompositeResultCode(result)
    except (TypeError, ValueError) as exc:
        raise InteropError(
            "unsupported composite result code; no semantic mapping was guessed"
        ) from exc
    if code is not CompositeResultCode.UNKNOWN and unknown_reason is not None:
        raise InteropError("unknown_reason is valid only for composite unknown")

    condition = {
        CompositeResultCode.PASS: EvidenceCondition.PROFILE_SATISFIED,
        CompositeResultCode.FAIL: EvidenceCondition.PROFILE_FAILED,
        CompositeResultCode.WARNING: EvidenceCondition.WARNING,
        CompositeResultCode.MISSING: EvidenceCondition.INCOMPLETE,
        CompositeResultCode.STALE: EvidenceCondition.STALE,
        CompositeResultCode.CONFLICT: EvidenceCondition.CONFLICTED,
        CompositeResultCode.NOT_APPLICABLE: EvidenceCondition.NOT_APPLICABLE,
    }.get(code)
    if code is CompositeResultCode.UNKNOWN:
        if unknown_reason is None:
            raise InteropError(
                "composite unknown needs an explicit reason to avoid collapsing causes"
            )
        condition = {
            UnknownReason.UNAVAILABLE_EVIDENCE: EvidenceCondition.UNAVAILABLE,
            UnknownReason.UNSUPPORTED_VERIFIER: EvidenceCondition.UNSUPPORTED_VERIFIER,
            UnknownReason.UNDECIDED: EvidenceCondition.BOUNDED_NOT_ESTABLISHED,
        }[unknown_reason]
    assert condition is not None
    return BoundedEvidenceResult(
        source_document=COMPOSITE_DRAFT,
        source_result=code.value,
        evidence_condition=condition,
        computational_verdict=COMPUTATIONAL_NOT_EVALUATED,
        reason=(
            "SCITT composite verification reports satisfaction of a selected "
            "evidence profile; it does not decide a VSTD computational predicate"
        ),
        limitations=(
            "registered or graph-consistent evidence can contain a false payload claim",
            "completeness depends on the selected profile and its discovery assumptions",
        ),
    )


def local_vstd_condition(name: str) -> EvidenceCondition:
    """Keep VSTD-side inability/falsification causes distinct for crosswalks."""

    mapping = {
        "revoked": EvidenceCondition.REVOKED,
        "superseded": EvidenceCondition.SUPERSEDED,
        "budget-exhausted": EvidenceCondition.BUDGET_EXHAUSTED,
        "not-established": EvidenceCondition.BOUNDED_NOT_ESTABLISHED,
        "falsified": EvidenceCondition.EXPLICITLY_FALSIFIED,
    }
    try:
        return mapping[name]
    except (KeyError, TypeError) as exc:
        raise InteropError("unsupported VSTD condition") from exc


class CoverageItemOutcome(str, Enum):
    MATCHED = "matched"
    OBSERVED_WITHOUT_RECEIPT = "observed-without-receipt"
    RECEIPTED_WITHOUT_OBSERVATION = "receipted-without-observation"
    EXCLUDED = "excluded"
    INDETERMINATE = "indeterminate"


class CoverageOverallOutcome(str, Enum):
    NO_EXCEPTIONS = "no-exceptions"
    EXCEPTIONS = "exceptions"
    INVALID_WINDOW = "invalid-window"


_COUNT_KEYS = {item.value for item in CoverageItemOutcome}
_OPEN_OUTCOMES = {
    CoverageItemOutcome.OBSERVED_WITHOUT_RECEIPT.value,
    CoverageItemOutcome.RECEIPTED_WITHOUT_OBSERVATION.value,
    CoverageItemOutcome.INDETERMINATE.value,
}


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise InteropError(
            f"{label} keys mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InteropError(f"{label} must be a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise InteropError(f"{label} must be sha256: followed by lowercase hex")
    return value


def consume_transformation_evidence(value: Mapping[str, Any]) -> BoundedEvidenceResult:
    """Validate the draft's closed transformation-evidence structure.

    The output records an issuer assertion.  Checking a signature, receipt,
    or this schema still does not prove the transformation was applied or
    that the protected value was unlearnable.
    """

    if not isinstance(value, Mapping):
        raise InteropError("transformation evidence must be an object")
    _exact_keys(value, {"v", "disclosure", "request", "policy", "classes"}, "transformation evidence")
    if value["v"] != "transformation-evidence/1":
        raise InteropError("unsupported transformation evidence version")
    _digest(value["disclosure"], "disclosure")
    _digest(value["request"], "request")
    policy = value["policy"]
    if not isinstance(policy, Mapping):
        raise InteropError("policy must be an object")
    _exact_keys(policy, {"id", "decision"}, "policy")
    _nonempty(policy["id"], "policy.id")
    _nonempty(policy["decision"], "policy.decision")
    classes = value["classes"]
    if not isinstance(classes, list):
        raise InteropError("classes must be an array")
    for index, item in enumerate(classes):
        if not isinstance(item, Mapping):
            raise InteropError(f"classes[{index}] must be an object")
        _exact_keys(item, {"class", "action", "count"}, f"classes[{index}]")
        _nonempty(item["class"], f"classes[{index}].class")
        if item["action"] not in {"mask", "redact", "tokenize", "truncate", "none"}:
            raise InteropError(f"classes[{index}].action is unsupported")
        if type(item["count"]) is not int or item["count"] < 0:
            raise InteropError(f"classes[{index}].count must be non-negative")
    return BoundedEvidenceResult(
        source_document=DISCLOSURE_DRAFT,
        source_result="transformation-evidence/1",
        evidence_condition=EvidenceCondition.ISSUER_ASSERTED,
        computational_verdict=COMPUTATIONAL_NOT_EVALUATED,
        reason="the signed payload records what the issuer asserts was transformed",
        limitations=(
            "schema, signature, and registration do not prove transformation execution",
            "transformation evidence does not prove non-exposure or unlearnability",
            "classes are bounded by the applied policy vocabulary",
        ),
    )


def consume_coverage_reconciliation(value: Mapping[str, Any]) -> BoundedEvidenceResult:
    """Validate essential ``coverage-reconciliation/2`` invariants.

    Item details remain mapping-profile-specific.  This function validates the
    common accounting surface and refuses the incompatible ``/1`` vocabulary.
    """

    if not isinstance(value, Mapping):
        raise InteropError("coverage reconciliation must be an object")
    expected = {
        "v",
        "window",
        "source",
        "snapshots",
        "receipts",
        "profile",
        "bounds",
        "outcome",
        "items",
        "counts",
    }
    _exact_keys(value, expected, "coverage reconciliation")
    if value["v"] != "coverage-reconciliation/2":
        raise InteropError(
            "unsupported coverage reconciliation version; /1 cannot be read as /2"
        )
    window = value["window"]
    if not isinstance(window, Mapping):
        raise InteropError("window must be an object")
    _exact_keys(window, {"start", "end"}, "window")
    _nonempty(window["start"], "window.start")
    _nonempty(window["end"], "window.end")
    _nonempty(value["source"], "source")
    snapshots = value["snapshots"]
    if not isinstance(snapshots, Mapping):
        raise InteropError("snapshots must be an object")
    _exact_keys(snapshots, {"start", "end"}, "snapshots")
    _digest(snapshots["start"], "snapshots.start")
    _digest(snapshots["end"], "snapshots.end")
    _digest(value["receipts"], "receipts")
    profile = value["profile"]
    if profile is not None:
        if not isinstance(profile, Mapping):
            raise InteropError("profile must be null or an object")
        _exact_keys(profile, {"id", "digest"}, "profile")
        _nonempty(profile["id"], "profile.id")
        _digest(profile["digest"], "profile.digest")
    bounds = value["bounds"]
    if not isinstance(bounds, Mapping):
        raise InteropError("bounds must be an object")
    for key, standing in bounds.items():
        _nonempty(key, "bounds key")
        if standing not in {
            "protocol-defined",
            "measured",
            "operator-declared",
            "undeclared",
        }:
            raise InteropError(f"bounds[{key!r}] has unsupported standing")
    try:
        overall = CoverageOverallOutcome(value["outcome"])
    except (TypeError, ValueError) as exc:
        raise InteropError("unsupported coverage reconciliation outcome") from exc
    counts = value["counts"]
    if not isinstance(counts, Mapping):
        raise InteropError("counts must be an object")
    _exact_keys(counts, _COUNT_KEYS, "counts")
    for key, count in counts.items():
        if type(count) is not int or count < 0:
            raise InteropError(f"counts[{key!r}] must be non-negative")
    items = value["items"]
    if not isinstance(items, list):
        raise InteropError("items must be an array")
    observed_item_counts = {key: 0 for key in _COUNT_KEYS - {"matched"}}
    for index, item in enumerate(items):
        if not isinstance(item, Mapping) or "outcome" not in item:
            raise InteropError(f"items[{index}] must name an outcome")
        try:
            item_outcome = CoverageItemOutcome(item["outcome"])
        except (TypeError, ValueError) as exc:
            raise InteropError(f"items[{index}] has unsupported outcome") from exc
        if item_outcome is CoverageItemOutcome.MATCHED:
            raise InteropError("matched items are represented only by counts")
        if item_outcome is CoverageItemOutcome.EXCLUDED:
            _nonempty(item.get("rule"), f"items[{index}].rule")
        observed_item_counts[item_outcome.value] += 1
    for key, count in observed_item_counts.items():
        if counts[key] != count:
            raise InteropError(f"counts[{key!r}] does not match items")
    open_count = sum(counts[key] for key in _OPEN_OUTCOMES)
    if overall is CoverageOverallOutcome.NO_EXCEPTIONS and open_count:
        raise InteropError("no-exceptions cannot contain open outcomes")
    if overall is CoverageOverallOutcome.EXCEPTIONS and not open_count:
        raise InteropError("exceptions requires at least one open outcome")

    condition = {
        CoverageOverallOutcome.NO_EXCEPTIONS: EvidenceCondition.RECONCILIATION_NO_EXCEPTIONS,
        CoverageOverallOutcome.EXCEPTIONS: EvidenceCondition.RECONCILIATION_EXCEPTIONS,
        CoverageOverallOutcome.INVALID_WINDOW: EvidenceCondition.INVALID_WINDOW,
    }[overall]
    limitations = [
        "the result compares two populations; neither population is assumed complete",
        "a digest-bound mapping profile reproduces choices but does not justify them",
        "coverage reconciliation does not evaluate a VSTD computational predicate",
    ]
    if counts[CoverageItemOutcome.EXCLUDED.value]:
        limitations.append("excluded items are visible and pinned, not proven appropriate")
    if any(standing == "operator-declared" for standing in bounds.values()):
        limitations.append("at least one bound has operator-declared standing")
    return BoundedEvidenceResult(
        source_document=DISCLOSURE_DRAFT,
        source_result=overall.value,
        evidence_condition=condition,
        computational_verdict=COMPUTATIONAL_NOT_EVALUATED,
        reason=(
            "the reconciliation outcome is evidence accounting under a declared "
            "mapping profile, not a bare coverage pass"
        ),
        limitations=tuple(limitations),
    )
