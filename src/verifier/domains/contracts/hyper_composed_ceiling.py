"""Current HYPER-3.1: the weakest operand bound is the composed ceiling.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits are bytes; meta-tiers, depths,
counts and checking budgets are dimensionless. An operand bound is the
uninterrupted tier prefix that its selected, replayed child certificates
establish. The composed object's own declaration never raises the ceiling.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Unavailable
from verifier.domains.contracts import hyper_unknown_absorption as absorption
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HYPER-3.1"
REQUEST_VERSION = "verifier-current-hyper-composed-ceiling-request-1"
POLICY_VERSION = "verifier-current-hyper-composed-ceiling-policy-1"
CERTIFICATE_VERSION = "verifier-current-hyper-composed-ceiling-certificate-1"
EVIDENCE_VERSION = "verifier-current-hyper-composed-ceiling-evidence-1"
MECHANISM_ID = "verifier.current-hyper.composed-ceiling.1"
SCOPE = "selected_direct_operand_tier_prefix_ceiling"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_objects": 256,
             "max_children": 64}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class HyperComposedCeilingError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "HYPER", "scope": SCOPE,
        "proposition": (
            "For one exact HYPER record in an exact retained typed collection, "
            "every selected child certificate is bound to one distinct direct "
            "operand record on that operand's own kind ladder and replays PASS "
            "through the registered current-object route; each direct "
            "operand's bound is the largest k such that selected children at "
            "meta-tiers 1 through k all replay PASS (zero when tier 1 is "
            "unselected); the composed ceiling is the minimum of those bounds "
            "whatever the HYPER payload declares, and the payload's "
            "declared_depth is a nonnegative integer not above that ceiling."),
        "row": ("HYPER-3.1 Composed ceiling: The weakest operand bound is the "
                "composed ceiling, whatever the composed object declares."),
        "prerequisites": [
            "exact HYPER record with payload declared_depth and complete "
            "retained typed collection",
            "at most one exact child request, policy and certificate per "
            "direct operand and meta-tier; finite checker limits"],
        "exclusions": [
            "object profile depth over every required coordinate; only the "
            "selected children are counted",
            "substrate recurrence, decider exteriority, manufacture "
            "impossibility and level independence (HYPER-3.2 to HYPER-3.5)",
            "operand verdict absorption beyond selected children (HYPER-2.3) "
            "and strength order or non-increase (HYPER-2.1, HYPER-2.2)",
            "whole HYPER statics tier or object-profile conformance",
            "authority, privacy, consent, governance, security or payload truth"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HyperComposedCeilingDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, HyperComposedCeilingError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, HyperComposedCeilingError)


def mechanism_digest() -> str:
    paths = dict(absorption.dependency_paths())
    paths[__name__] = Path(__file__)
    standard = Path(__file__).parents[2] / "standard"
    for name in ("CURRENT_HYPER_COMPOSED_CEILING.md", "LADDER.md", "META_TIERS.md"):
        paths[name] = standard / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=HyperComposedCeilingError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def hyper_composed_ceiling_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "child_selections",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "HYPER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise HyperComposedCeilingError("selected HYPER-3.1 objective differs")
    if (type(selected["subject_id"]) is not str or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise HyperComposedCeilingError("bounded HYPER subject required")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, HyperComposedCeilingError)
    selected["child_selections"] = absorption.select_children(
        selected["child_selections"], max_children=selected["limits"]["max_children"],
        by_tier=True, error_type=HyperComposedCeilingError)
    return selected


def hyper_composed_ceiling_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_selections: list[dict[str, Any]],
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise HyperComposedCeilingError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "HYPER",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_selections": child_selections, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        value, budget = absorption.read_evidence(data, request, EVIDENCE_VERSION)
        operands, root, rows = absorption.bound_children(
            value, request, budget, kind_must_match=True)
        selected = {target: {} for target in operands}
        for row in rows:
            selected[row["target"]][str(row["tier"])] = row["status"]
        if any(row["status"] == "UNKNOWN" for row in rows):
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                "a selected child replays UNKNOWN, so its operand bound is UNKNOWN",
                {"selected_tiers": selected})
        if any(row["status"] == "FAIL" for row in rows):
            return MechanismDecision(MechanismOutcome.FAIL,
                "a selected establishing child replays FAIL",
                {"selected_tiers": selected})
        prefixes = {}
        for target in operands:
            passed = {row["tier"] for row in rows if row["target"] == target}
            depth = 0
            while depth + 1 in passed:
                budget.tick()
                depth += 1
            prefixes[target] = depth
        composed = min(prefixes.values())
        payload = root.payload
        if "declared_depth" not in payload:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                "the composed object declares no depth",
                {"operand_prefixes": prefixes, "composed_ceiling": composed})
        declared = common_module.integer(payload["declared_depth"])
        observations = {"operand_prefixes": prefixes, "composed_ceiling": composed,
                        "declared_depth": declared, "operations": budget.used}
        if declared > composed:
            return MechanismDecision(MechanismOutcome.FAIL,
                "the composed object declares a depth above its weakest operand bound",
                observations)
        return MechanismDecision(MechanismOutcome.PASS,
            "the declared depth does not exceed the weakest operand bound", observations)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _Mechanism:
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
                                     "bound HYPER-3.1 proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected composition bundle required")
        return _evaluate(evidence[0], self.request)


_NOT_ESTABLISHED = ("hyper_statics_tier", "substrate_recurrence",
    "decider_exteriority", "manufacture_impossibility", "level_independence",
    "object_profile_depth", "authority", "privacy", "consent", "governance",
    "security", "object_profile_conformance")


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HyperComposedCeilingError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_Mechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "HYPER", "scope": SCOPE,
        "composed_ceiling_bound": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        **{field: "NOT_ESTABLISHED" for field in _NOT_ESTABLISHED},
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
        raise HyperComposedCeilingError("certificate byte bound exhausted")
    return encoded


def build_hyper_composed_ceiling_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise HyperComposedCeilingError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HyperComposedCeilingError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_hyper_composed_ceiling_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise HyperComposedCeilingError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise HyperComposedCeilingError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HyperComposedCeilingError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HyperComposedCeilingError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, HyperComposedCeilingError):
            raise
        raise HyperComposedCeilingError(
            "invalid retained HYPER-3.1 certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST",
           "HyperComposedCeilingDescriptor", "HyperComposedCeilingError",
           "registration", "hyper_composed_ceiling_policy",
           "hyper_composed_ceiling_request",
           "build_hyper_composed_ceiling_certificate",
           "recheck_hyper_composed_ceiling_certificate"]
