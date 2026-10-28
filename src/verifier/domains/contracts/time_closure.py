"""Current TIME-4.1: externally selected declared-clock sample inventory closure.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); identifier (ID). Microseconds belong to one declared clock.
Counts and budgets are dimensionless. Exact inventory and terminal boundary
selection do not prove physical-clock truth, event causality, actual termination,
sampling continuity, authoritative inventory completeness or whole-tier closure.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, time_order


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "TIME-4.1"
REQUEST_VERSION = "verifier-current-time-closure-request-1"
POLICY_VERSION = "verifier-current-time-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-time-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-time-closure-evidence-1"
MECHANISM_ID = "verifier.current-time.declared-inventory-closure.1"
SCOPE = "selected_declared_clock_inventory_closure"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_nesting_depth": 48}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_SAFE_INTEGER = 2**53 - 1
INVENTORY_VERSION = "verifier-current-time-closure-inventory-1"


class TimeClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


class TimeClosureUnavailable(OSError):
    """Certificate checking is unavailable; public routes preserve UNKNOWN."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "TIME", "scope": SCOPE,
        "proposition": (
            "The independently selected exact TIME-2.1 child replays PASS; its "
            "retained ordered sample rows equal the independently selected finite "
            "inventory, with the exact selected root and terminal sample IDs, "
            "declared clock, half-open span and exclusive terminal cutoff."),
        "prerequisites": [
            "exact external TIME-2.1 request, policy and certificate selection",
            "independently selected complete-byte finite sample inventory, "
            "count, root/terminal IDs and declared clock/span/cutoff",
            "finite checking limits and child replay PASS"],
        "exclusions": [
            "authoritative inventory completeness beyond the external selection",
            "physical clock identity, calibration, skew or wall-clock truth",
            "cross-clock synchronization or physical event causality",
            "any EVENT-to-sample mapping or truth of EVENT operands",
            "continuous temporal coverage, sample density or minimum spacing",
            "actual termination, append-only behaviour or later continuation",
            "whole TIME closure tier or object-profile conformance",
            "privacy, consent, governance and security admission"]}

PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class TimeClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, TimeClosureError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, TimeClosureError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module,
               common_module, retained_selection, time_order)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TIME_ORDER.md",
                 "CURRENT_TIME_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes"}, "policy")
    if type(selected["trust_roots"]) is list:
        selected["trust_roots"] = list(selected["trust_roots"])
    return retained_selection.policy(selected, error_type=TimeClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def time_closure_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise TimeClosureError(label + " must be a nonnegative safe integer")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise TimeClosureError(label + " requires bounded nonempty text")
    return value


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "child_request_digest",
        "child_policy_digest", "child_certificate_digest", "inventory_digest",
        "inventory_count", "root_sample_id", "terminal_sample_id", "clock",
        "span_start_us", "span_end_us", "cutoff_us", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
            ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
            ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "TIME")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise TimeClosureError("selected declared inventory closure differs")
    for field in ("subject_id", "root_sample_id", "terminal_sample_id", "clock"):
        _text(selected[field], field)
    for field in ("object_digest", "collection_digest", "child_request_digest",
            "child_policy_digest", "child_certificate_digest", "inventory_digest",
            "evidence_ref", "policy_digest"):
        _digest(selected[field])
    for field in ("span_start_us", "span_end_us", "cutoff_us"):
        _integer(selected[field], field)
    if selected["span_start_us"] >= selected["span_end_us"]:
        raise TimeClosureError("selected declared span must be nonempty")
    if selected["cutoff_us"] != selected["span_end_us"]:
        raise TimeClosureError("terminal cutoff must equal the exclusive span end")
    if (type(selected["inventory_count"]) is not int
            or not 1 <= selected["inventory_count"] <= _CEILINGS["max_items"]):
        raise TimeClosureError("selected inventory count is unsupported")
    selected["limits"] = retained_selection.limits(selected["limits"],
        _CEILINGS, TimeClosureError)
    return selected


def time_closure_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        inventory_digest: str, inventory_count: int, root_sample_id: str,
        terminal_sample_id: str, clock: str, span_start_us: int,
        span_end_us: int, cutoff_us: int, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise TimeClosureError("unsupported limit override")
    owned_limits = retained_selection.limits({**_CEILINGS, **(limits or {})},
        _CEILINGS, TimeClosureError)
    admitted = _policy(policy)
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "TIME",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "inventory_digest": inventory_digest, "inventory_count": inventory_count,
        "root_sample_id": root_sample_id, "terminal_sample_id": terminal_sample_id,
        "clock": clock, "span_start_us": span_start_us,
        "span_end_us": span_end_us, "cutoff_us": cutoff_us,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": owned_limits})

def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _preflight(data: bytes, maximum_depth: int) -> None:
    """Bound decoder recursion/decimal integers before recursive parsing."""
    depth = digits = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif 48 <= byte <= 57:
            digits += 1
            if digits > 1234:
                raise Unavailable("closure integer checking bound exhausted")
        elif byte == 34:
            digits = 0
            quoted = True
        elif byte in (91, 123):
            digits = 0
            depth += 1
            if depth > maximum_depth:
                raise Unavailable("closure nesting checking bound exhausted")
        elif byte in (93, 125):
            digits = 0
            depth -= 1
        else:
            digits = 0


def _inventory(value: Any, request: dict[str, Any],
               budget: common_module.Budget) -> dict[str, Any]:
    if value is None:
        raise Unavailable("selected retained inventory is absent")
    inventory = _record(value, {"schema_version", "subject_id",
        "object_digest", "collection_digest", "clock", "unit", "span_start_us",
        "span_end_us", "cutoff_us", "root_sample_id", "terminal_sample_id",
        "samples"}, "inventory")
    if "sha256:" + canonical_digest(inventory) != request["inventory_digest"]:
        raise Refuted("independently selected inventory differs")
    for field, expected in (("schema_version", INVENTORY_VERSION),
            ("unit", "microsecond"),
            *((field, request[field]) for field in ("subject_id", "object_digest",
                "collection_digest", "clock", "span_start_us", "span_end_us",
                "cutoff_us", "root_sample_id", "terminal_sample_id"))):
        if type(inventory[field]) is not type(expected) or inventory[field] != expected:
            raise Refuted("inventory " + field + " differs from external selection")
    required = inventory["samples"]
    if type(required) is not list:
        raise Refuted("inventory samples require an ordered list")
    if len(required) > request["limits"]["max_items"]:
        raise Unavailable("selected sample comparison bound exhausted")
    if len(required) != request["inventory_count"]:
        raise Refuted("selected inventory count differs")
    seen: set[str] = set()
    previous = None
    for sample in required:
        budget.tick()
        sample = _record(sample, {"id", "at_us"}, "inventory sample")
        identifier = _text(sample["id"], "inventory sample ID")
        instant = _integer(sample["at_us"], "inventory sample instant")
        if identifier in seen:
            raise Refuted("duplicate inventory sample ID")
        seen.add(identifier)
        if not request["span_start_us"] <= instant < request["span_end_us"]:
            raise Refuted("inventory sample is outside selected half-open span")
        if previous is not None and instant < previous:
            raise Refuted("inventory contradicts required nondecreasing child order")
        previous = instant
    if (required[0]["id"] != request["root_sample_id"]
            or required[-1]["id"] != request["terminal_sample_id"]):
        raise Refuted("selected inventory root or terminal sample differs")
    return inventory


def _child_subject(candidate: dict[str, Any], request: dict[str, Any]) -> None:
    if (candidate["subject_id"] != request["subject_id"]
            or candidate["object_digest"] != request["object_digest"]
            or candidate["collection_digest"] != request["collection_digest"]
            or candidate["semantic_version"] != time_order.SEMANTIC_VERSION
            or candidate["coordinate"] != time_order.COORDINATE
            or candidate["object_kind"] != "TIME"):
        raise Refuted("child is not the selected TIME-2.1 subject")


def _child(value: dict[str, Any], request: dict[str, Any]) -> tuple[Any, Any]:
    child_request, child_policy = value["child_request"], value["child_policy"]
    unknown: list[str] = []
    admitted_policy = child_certificate = child_data = None
    # Sweep every present component before deciding that missing support
    # prevents replay. Null policy must not hide a substituted request/certificate.
    if child_request is None:
        unknown.append("selected retained child request is absent")
    else:
        if "sha256:" + canonical_digest(child_request) != request["child_request_digest"]:
            raise Refuted("selected child request differs")
        try:
            child_request = time_order._request(child_request)
        except time_order.TimeOrderError as exc:
            raise Refuted("selected child request is malformed") from exc
        _child_subject(child_request, request)
    if child_policy is None:
        unknown.append("selected retained child policy is absent")
    else:
        if "sha256:" + canonical_digest(child_policy) != request["child_policy_digest"]:
            raise Refuted("selected child policy differs")
        child_policy = _record(child_policy, {"schema_version", "mechanism_id",
            "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "child policy")
        if (child_policy["schema_version"] != time_order.POLICY_VERSION
                or child_policy["mechanism_id"] != time_order.MECHANISM_ID):
            raise Refuted("child policy version or mechanism differs")
        _digest(child_policy["mechanism_digest"])
        roots = child_policy["trust_roots"]
        if (type(roots) is not list or not 1 <= len(roots) <= 16
                or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
                or roots != sorted(set(roots))):
            raise Refuted("child policy trust-root labels are malformed")
        size = child_policy["max_certificate_bytes"]
        if type(size) is not int or not 1 <= size <= time_order._MAX_CERTIFICATE_BYTES:
            raise Refuted("child policy certificate byte limit is malformed")
        if child_request is not None and child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy):
            raise Refuted("selected child request does not bind the selected child policy")
        try:
            admitted_policy = time_order._policy(child_policy)
        except time_order.TimeOrderError as exc:
            raise Refuted("selected child policy is malformed or unsupported") from exc
        except (Unavailable, ImportError, OSError, RecursionError, OverflowError) as exc:
            unknown.append(str(exc))
    if value["child_certificate"] is None:
        unknown.append("selected retained child certificate is absent")
    else:
        child_certificate = _decode_b64(value["child_certificate"], "child certificate")
        if ("sha256:" + hashlib.sha256(child_certificate).hexdigest()
                != request["child_certificate_digest"]):
            raise Refuted("selected child certificate differs")
        if len(child_certificate) > time_order._MAX_CERTIFICATE_BYTES:
            raise Unavailable("child certificate bound exhausted")
        _preflight(child_certificate, request["limits"]["max_nesting_depth"])
        child = _record(strict_json_loads(child_certificate.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "child certificate")
        if (canonical_bytes(child) != child_certificate
                or child["schema_version"] != time_order.CERTIFICATE_VERSION
                or child["proposition_digest"] != time_order.PROPOSITION_DIGEST):
            raise Refuted("child certificate canonical version or proposition differs")
        for field in ("policy_digest", "mechanism_digest", "proposition_digest", "digest"):
            _digest(child[field])
        if type(child["result"]) is not dict:
            raise Refuted("child certificate result must be a plain record")
        body = {key: item for key, item in child.items() if key != "digest"}
        if child["digest"] != "sha256:" + canonical_digest(body):
            raise Refuted("child certificate envelope digest differs")
        try:
            embedded_request = time_order._request(child["request"])
        except time_order.TimeOrderError as exc:
            raise Refuted("child certificate request is malformed") from exc
        _child_subject(embedded_request, request)
        if child_request is not None and embedded_request != child_request:
            raise Refuted("child certificate differs from selected child request")
        if child["policy_digest"] != embedded_request["policy_digest"]:
            raise Refuted("child certificate policy selection differs")
        if child_policy is not None and child["policy_digest"] != "sha256:" + canonical_digest(child_policy):
            raise Refuted("child certificate differs from selected child policy")
        if admitted_policy is not None and child["mechanism_digest"] != admitted_policy["mechanism_digest"]:
            raise Refuted("child certificate mechanism differs from admitted child policy")
        payloads = child["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {embedded_request["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())
                or child["evidence_refs"] != [embedded_request["evidence_ref"]]):
            raise Refuted("child retained evidence container differs")
        if embedded_request["evidence_ref"] in payloads:
            child_data = _decode_b64(payloads[embedded_request["evidence_ref"]], "child retained evidence")
            if "sha256:" + hashlib.sha256(child_data).hexdigest() != embedded_request["evidence_ref"]:
                raise Refuted("child retained evidence reference differs")
            _preflight(child_data, request["limits"]["max_nesting_depth"])
    if unknown:
        raise Unavailable("; ".join(unknown))
    try:
        child_result = time_order.recheck_time_order_certificate(child_certificate,
            expected_request=child_request, policy=child_policy)
    except time_order.TimeOrderError as exc:
        raise Refuted("selected TIME-2.1 child does not replay") from exc
    if child_result["status"] == "UNKNOWN":
        raise Unavailable("selected TIME-2.1 child remains UNKNOWN")
    if child_result["status"] != "PASS":
        raise Refuted("selected TIME-2.1 child did not pass")
    if child_data is None:
        raise Unavailable("selected child retained evidence is absent")
    retained = strict_json_loads(child_data.decode("utf-8"))
    payload = next(row["payload"] for row in retained["objects"]
        if row["object_id"] == request["subject_id"])
    return payload, retained["inputs"]["samples"]


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        _preflight(data, limits["max_nesting_depth"])
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "child_request", "child_policy", "child_certificate",
             "inventory"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained closure evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        unknown: list[str] = []
        inventory = payload = samples = None
        # Inventory predicates have their own selected inputs. A missing child
        # cannot hide an inspected inventory contradiction.
        try:
            inventory = _inventory(value["inventory"], request, budget)
        except (Unavailable, ImportError, OSError, RecursionError, OverflowError) as exc:
            unknown.append(str(exc))
        # Conversely, absent inventory cannot erase a genuinely replayed FAIL.
        try:
            payload, samples = _child(value, request)
        except (Unavailable, ImportError, OSError, RecursionError, OverflowError) as exc:
            unknown.append(str(exc))
        if unknown:
            raise Unavailable("; ".join(unknown))
        for field in ("clock", "unit", "span_start_us", "span_end_us"):
            if type(payload[field]) is not type(inventory[field]) or payload[field] != inventory[field]:
                raise Refuted("selected declared clock or span differs")
        if len(samples) > limits["max_items"]:
            raise Unavailable("selected sample comparison bound exhausted")
        if canonical_bytes(samples) != canonical_bytes(inventory["samples"]):
            raise Refuted("retained inventory differs from the exact selected child")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected declared sample inventory and exclusive terminal boundary reproduced",
            {"samples": len(samples), "cutoff_us": request["cutoff_us"],
             "operations": budget.used})
    except (Unavailable, ImportError, OSError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            AttributeError, StopIteration) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _TimeClosureMechanism:
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
                                     "bound TIME closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TimeClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_TimeClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "TIME", "scope": SCOPE,
        "selected_inventory_closure": "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
        "external_inventory_completeness": "NOT_ESTABLISHED",
        "physical_clock_truth": "NOT_ESTABLISHED", "cross_clock_synchronization": "NOT_ESTABLISHED",
        "causal_order": "NOT_ESTABLISHED", "event_to_sample_binding": "NOT_ESTABLISHED",
        "continuous_temporal_coverage": "NOT_ESTABLISHED", "minimum_spacing": "NOT_ESTABLISHED",
        "actual_termination": "NOT_ESTABLISHED", "append_only_history": "NOT_ESTABLISHED",
        "whole_time_closure": "NOT_ESTABLISHED", "object_profile_conformance": "NOT_ESTABLISHED",
        "privacy": "NOT_ESTABLISHED", "consent": "NOT_ESTABLISHED",
        "governance": "NOT_ESTABLISHED", "security": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise TimeClosureError("certificate byte bound exhausted")
    return encoded


def build_time_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise TimeClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TimeClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_time_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes:
        raise TimeClosureError("immutable certificate bytes required")
    if len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TimeClosureUnavailable("selected certificate byte checking bound exhausted")
    try:
        _preflight(certificate_bytes, _CEILINGS["max_nesting_depth"])
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise TimeClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise TimeClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TimeClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise TimeClosureUnavailable("retained certificate checking unavailable: " + str(exc)) from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, TimeClosureError):
            raise
        raise TimeClosureError("invalid retained TIME closure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "INVENTORY_VERSION", "PROPOSITION_DIGEST", "TimeClosureDescriptor",
           "TimeClosureError", "TimeClosureUnavailable", "registration", "time_closure_policy",
           "time_closure_request", "build_time_closure_certificate",
           "recheck_time_closure_certificate"]
