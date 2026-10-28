"""Exact finite inventory admission relative to independently selected operator roots.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); hash-based message authentication code (HMAC). The retained
symmetric governance engine authenticates statements relative to caller-provisioned
secret keys. Key holders can construct those statements. This prerequisite retains
open normative completeness, native objective truth and public-proof gates. Byte
bounds use bytes; counts are dimensionless; clocks use integer Unix seconds.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from verifier.governance import (
    GovernanceContext, GovernanceEvaluation, GovernancePolicy, GovernanceVerdict,
    _capture_policy, evaluate_governance, policy_digest, recheck_governance,
)
from verifier.runtime import polish_inventory
from verifier.runtime.polish_inventory import assess_objective_inventory, recheck_objective_inventory


OPERATION = "ADMIT_SELECTED_POLISH_INVENTORY"
SUBJECT_VERSION = "verifier-polish-inventory-authority-subject-1"
REQUEST_VERSION = "verifier-polish-inventory-authority-request-1"
ASSESSMENT_VERSION = "verifier-polish-inventory-authority-assessment-1"
REPLAY_VERSION = "verifier-polish-inventory-authority-replay-1"
_BOUNDS = {"plan": 8 * 1024**2, "profile": 4 * 1024**2, "collection": 32 * 1024**2,
           "inventory_request": 1024**2, "authority_request": 1024**2, "authority_evidence": 1024**2}
_OUTPUT_BOUND = 4 * 1024**2
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ROOT_HASH = re.compile(r"[0-9a-f]{64}\Z")
BOUNDARY = ("Operator admission of an exact finite selected application profile and its derived applicability "
            "relative to independently supplied symmetric roots only. Normative inventory completeness, "
            "native objective truth, whole-tier conformance and public proof remain unestablished. "
            "No positive polish, publication, execution or invocation consumption.")


class InventoryAuthorityUnavailable(RuntimeError):
    """The selected inventory cannot yet supply a complete finite signing subject."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    """Bind the executed admission, retained engines and packaged specifications."""
    root = Path(__file__).parents[1]
    names = ("runtime/polish_inventory_authority.py", "governance/__init__.py",
             "core/certificate.py", "core/receipt.py", "standard/POLISH_INVENTORY_AUTHORITY.md")
    return _digest(canonical_bytes({"sources": {name: _digest((root / name).read_bytes()) for name in names},
                                  "inventory_mechanism": polish_inventory.mechanism_digest()}))


def _admit(raw: bytes, bound: int) -> None:
    if type(raw) is not bytes or len(raw) > bound:
        raise ValueError("immutable bounded transport required")


def _plain(value: Any) -> Any:
    """Capture returned evidence before serialization or independent replay."""
    nodes = 0
    byte_count = 0

    def copy(item: Any, depth: int) -> Any:
        nonlocal nodes, byte_count
        nodes += 1
        if nodes > 50000 or depth > 64:
            raise ValueError("returned evidence structural bound exhausted")
        kind = type(item)
        if kind is dict:
            if len(item) > 32768:
                raise ValueError("returned evidence object bound exhausted")
            entries = tuple(item.items())
            result = {}
            for key, child in entries:
                if type(key) is not str:
                    raise ValueError("plain evidence keys required")
                result[copy(key, depth + 1)] = copy(child, depth + 1)
            return result
        if kind is list or kind is tuple:
            if len(item) > 32768:
                raise ValueError("returned evidence array bound exhausted")
            return [copy(child, depth + 1) for child in tuple(item)]
        if kind is str:
            if len(item) > _OUTPUT_BOUND - byte_count:
                raise ValueError("returned evidence text bound exhausted")
            byte_count += len(item.encode("utf-8"))
            if byte_count > _OUTPUT_BOUND:
                raise ValueError("returned evidence text bound exhausted")
            return item
        if kind is int:
            if item.bit_length() > 4096:
                raise ValueError("returned evidence integer bound exhausted")
            return item
        if kind is float and math.isfinite(item):
            return item
        if item is None or kind is bool:
            return item
        raise ValueError("returned evidence must contain only plain data")

    return copy(value, 0)


def _load(raw: bytes, bound: int) -> dict[str, Any]:
    _admit(raw, bound)
    result = strict_json_loads(raw.decode("utf-8"))
    if type(result) is not dict:
        raise ValueError("plain object transport required")
    return result


def _selection(raw: bytes, source: str) -> dict[str, Any]:
    selected = _load(raw, _BOUNDS["authority_request"])
    if set(selected) != {"schema_version", "mechanism_digest", "subject_digest", "policy_digest",
                         "actor_id", "observer_id", "purpose", "timestamp", "jurisdiction",
                         "invocation_id", "admitted_inapplicability"}:
        raise ValueError("unknown authority selection fields")
    if selected["schema_version"] != REQUEST_VERSION or selected["mechanism_digest"] != source:
        raise ValueError("selected admission mechanism differs")
    if type(selected["subject_digest"]) is not str or _HASH.fullmatch(selected["subject_digest"]) is None:
        raise ValueError("exact subject byte digest required")
    if type(selected["policy_digest"]) is not str or _ROOT_HASH.fullmatch(selected["policy_digest"]) is None:
        raise ValueError("selected public policy commitment required")
    for field in ("actor_id", "observer_id", "purpose", "jurisdiction", "invocation_id"):
        value = selected[field]
        if type(value) is not str or not value.strip() or len(value) > 512:
            raise ValueError("bounded authority identifiers required")
    if type(selected["timestamp"]) is not int or not 0 <= selected["timestamp"] < 2**63:
        raise ValueError("bounded integer authority time required")
    if type(selected["admitted_inapplicability"]) is not list:
        raise ValueError("exact inapplicability selection required")
    return selected


def _subject(retained: dict[str, bytes | None], report: dict[str, Any], source: str) -> dict[str, Any]:
    plan = _load(retained["plan"], _BOUNDS["plan"])
    omitted = [row for row in plan["requirements"] if row["applicability"] == "NOT_APPLICABLE"]
    return {"schema_version": SUBJECT_VERSION, "operation": OPERATION,
        "authority_mechanism_digest": source, "inventory_assessment_digest": report["assessment_digest"],
        "input_digests": {name: _digest(retained[name]) for name in (
            "plan", "profile", "collection", "inventory_request")},
        "root_id": report["root_id"], "profile_digest": report["profile_digest"],
        "collection_digest": report["collection_digest"], "admitted_inapplicability": omitted}


def _inventory_report(retained: dict[str, bytes | None]) -> dict[str, Any]:
    native = _plain(assess_objective_inventory(retained["plan"], profile_bytes=retained["profile"],
        collection_bytes=retained["collection"], request_bytes=retained["inventory_request"]))
    replay = recheck_objective_inventory(canonical_bytes(native), plan_bytes=retained["plan"],
        profile_bytes=retained["profile"], collection_bytes=retained["collection"],
        request_bytes=retained["inventory_request"])
    if replay.get("replay_status") != "REPRODUCED" or replay.get("status") != native["status"]:
        raise ValueError("selected inventory evidence cannot independently replay")
    return native


def _subject_available(native: dict[str, Any]) -> bool:
    return (native["status"] == "PASS" or native["status"] == "UNKNOWN"
            and native.get("profile_plan_coverage") == "PASS" and "reason" not in native)


def build_inventory_authority_subject(*, plan_bytes: bytes, profile_bytes: bytes,
                                     collection_bytes: bytes, inventory_request_bytes: bytes) -> bytes:
    """Format a replayed finite signing subject without admitting authority or signing."""
    retained = {"plan": plan_bytes, "profile": profile_bytes, "collection": collection_bytes,
                "inventory_request": inventory_request_bytes}
    for name, raw in retained.items():
        _admit(raw, _BOUNDS[name])
    try:
        source = mechanism_digest()
        native = _inventory_report(retained)
    except OSError as error:
        raise InventoryAuthorityUnavailable("selected mechanism is unavailable") from error
    if native["status"] == "FAIL":
        raise ValueError("selected inventory is refuted")
    if not _subject_available(native):
        raise InventoryAuthorityUnavailable("complete derived inventory subject is unavailable")
    result = canonical_bytes(_subject(retained, native, source))
    _admit(result, _BOUNDS["authority_request"])
    return result


def assess_inventory_authority(*, plan_bytes: bytes, profile_bytes: bytes, collection_bytes: bytes,
                              inventory_request_bytes: bytes, authority_request_bytes: bytes,
                              authority_evidence_bytes: bytes | None,
                              policy: GovernancePolicy | None,
                              evaluation_time: int | None) -> dict[str, Any]:
    """Replay the selected inventory and its distinct signed operator admission."""
    report: dict[str, Any] = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "inventory_status": "NOT_EVALUATED", "profile_authority_status": "NOT_EVALUATED",
        "inapplicability_authority_status": "NOT_EVALUATED", "polished": False,
        "objective_inventory_closure": "NOT_ESTABLISHED", "native_objective_truth": "NOT_EVALUATED",
        "public_checkability": "NOT_ESTABLISHED", "invocation_consumption": "NOT_PERFORMED",
        "replayable": False, "claim_boundary": BOUNDARY}
    try:
        retained = {"plan": plan_bytes, "profile": profile_bytes, "collection": collection_bytes,
            "inventory_request": inventory_request_bytes, "authority_request": authority_request_bytes,
            "authority_evidence": authority_evidence_bytes}
        for name, raw in retained.items():
            if name == "authority_evidence" and raw is None:
                continue
            _admit(raw, _BOUNDS[name])
        if evaluation_time is not None and (type(evaluation_time) is not int or not 0 <= evaluation_time < 2**63):
            raise ValueError("independent bounded integer clock required")
        if policy is not None:
            policy = _capture_policy(policy)
        source = mechanism_digest()
        selected = _selection(authority_request_bytes, source)
        evidence = {"decisions": [], "status": None} if authority_evidence_bytes is None else _load(
            authority_evidence_bytes, _BOUNDS["authority_evidence"])
        if set(evidence) != {"decisions", "status"} or type(evidence["decisions"]) is not list:
            raise ValueError("exact authority evidence inventory required")
        if len(evidence["decisions"]) > 256:
            raise ValueError("authority decision inventory exceeds bound")
        if policy is not None and selected["policy_digest"] != policy_digest(policy):
            raise ValueError("selected operator policy differs")
        report.update(mechanism_digest=source, evaluation_time=evaluation_time,
            selected_policy_digest=selected["policy_digest"],
            input_digests={name: None if raw is None else _digest(raw) for name, raw in retained.items()},
            replayable=True)
        native = _inventory_report(retained)
        report.update(inventory_status=native["status"], inventory_assessment=native)
        if not _subject_available(native):
            report["status"] = native["status"]
        else:
            subject = _subject(retained, native, source)
            subject_digest = _digest(canonical_bytes(subject))
            if (selected["subject_digest"] != subject_digest or
                    canonical_bytes(selected["admitted_inapplicability"]) != canonical_bytes(subject["admitted_inapplicability"])):
                raise ValueError("selected signed subject or inapplicability differs")
            context = GovernanceContext("OBJECT", subject_digest[7:], OPERATION,
                selected["actor_id"], selected["observer_id"], selected["purpose"],
                selected["timestamp"], selected["jurisdiction"], selected["invocation_id"])
            decisions = tuple(evidence["decisions"])
            governance = evaluate_governance(context, decisions, policy=policy, status=evidence["status"],
                evaluation_time=evaluation_time, computational_verdict=native["status"])
            if type(governance) is not GovernanceEvaluation or type(governance.verdict) is not GovernanceVerdict:
                raise ValueError("plain returned governance evidence required")
            receipt = _plain(governance.receipt)
            if (receipt.get("verdict") != governance.verdict.value or recheck_governance(
                    receipt, context, decisions, policy=policy, status=evidence["status"],
                    evaluation_time=evaluation_time, computational_verdict=native["status"]) is not True):
                raise ValueError("operator admission evidence cannot independently replay")
            verdict = governance.verdict.value
            if selected["actor_id"] in receipt["approving_actors"]:
                raise ValueError("selected submitter cannot supply its own approval")
            admitted = "UNKNOWN" if native["status"] == "UNKNOWN" and verdict == "PASS" else verdict
            report.update(status="FAIL" if admitted == "REJECTED" else admitted,
                profile_authority_status=admitted, inapplicability_authority_status=admitted,
                subject_digest=subject_digest, governance_receipt=receipt,
                admitted_inapplicability_count=len(subject["admitted_inapplicability"]))
    except OSError:
        report.update(status="UNKNOWN", reason="MECHANISM_UNAVAILABLE", replayable=False)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        report.update(status="FAIL", reason="INVALID_OR_SUBSTITUTED_INPUT")
    if report["replayable"]:
        raw = canonical_bytes(report)
        if len(raw) > _OUTPUT_BOUND:
            return {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN", "polished": False,
                    "reason": "RESOURCE_LIMIT_EXCEEDED", "replayable": False, "claim_boundary": BOUNDARY}
        report["assessment_digest"] = _digest(raw)
    return report


def recheck_inventory_authority(assessment_bytes: bytes, **external_selection: Any) -> dict[str, Any]:
    """Recompute with external inputs and current roots, comparing canonical bytes."""
    result: dict[str, Any] = {"schema_version": REPLAY_VERSION, "status": "FAIL",
        "replay_status": "REJECTED", "polished": False, "claim_boundary": BOUNDARY}
    try:
        stored = _load(assessment_bytes, _OUTPUT_BOUND)
        expected = assess_inventory_authority(**external_selection)
        if expected["replayable"] is True and canonical_bytes(stored) == canonical_bytes(expected):
            result.update(status=expected["status"], replay_status="REPRODUCED",
                          assessment_digest=expected["assessment_digest"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        pass
    return result
