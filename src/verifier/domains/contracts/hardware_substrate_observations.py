"""Current HARDWARE-3.1: retained qualified substrate-observation records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); platform configuration register (PCR). Instants
and freshness bounds are integer microseconds on one named clock. Register
values and event digests are 32-byte SHA-256 outputs written as 64 lowercase
hexadecimal characters. Counts, register indices and budgets are
dimensionless. This check authenticates no device, observer, signature,
quote or clock; a declaration without a qualified record stays UNKNOWN.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HARDWARE-3.1"
REQUEST_VERSION = "verifier-current-hardware-substrate-observations-request-1"
POLICY_VERSION = "verifier-current-hardware-substrate-observations-policy-1"
CERTIFICATE_VERSION = "verifier-current-hardware-substrate-observations-certificate-1"
EVIDENCE_VERSION = "verifier-current-hardware-substrate-observations-evidence-1"
MECHANISM_ID = "verifier.current-hardware.qualified-substrate-observations.1"
SCOPE = "retained_qualified_substrate_observation_records"
SUBJECT_SCOPE = "retained-hardware-records"
# The five categories named by the governing DOMAIN_OBLIGATIONS row. The label
# is carried and counted; it never changes which check applies.
CATEGORIES = ("calibration", "device_identity", "live_availability",
              "physical_capacity", "sensor_accuracy")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INSTANT_US = 2**53 - 1
_MAX_REGISTER = 65535
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_claims": 1024, "max_observations": 4096, "max_events": 4096,
    "max_event_bytes": 65536,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_SCOPE_FIELD = "qualified_observation_record_coverage"
_EXCLUDED_FIELDS = (
    "device_identity", "physical_capacity", "calibration", "sensor_accuracy",
    "live_availability", "observation_authenticity",
    "quote_signature_authenticity", "event_log_completeness",
    "clock_authenticity", "legacy_hardware_statics",
    "hardware_statics_tier_conformance", "object_profile_conformance",
    "privacy", "consent", "governance", "security",
)


class HardwareSubstrateObservationsError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "HARDWARE",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact HARDWARE namespace record occurs in "
            "the selected finite typed collection and its retained substrate "
            "claims and observation records rehash. Every retained claim has at "
            "least one retained observation record qualified at the externally "
            "selected instant: its explicit closed freshness interval on the "
            "selected clock contains that instant and its trust-root reference "
            "is in the policy's admitted set. Every qualified record states "
            "exactly the declared value, and every retained measured-boot "
            "record's event log replays by SHA-256 extend from 32 zero bytes to "
            "the register quote it states."
        ),
        "prerequisites": [
            "independently selected exact HARDWARE record, collection, "
            "evaluation clock and instant, retained claim and observation "
            "bytes, admitted trust-root labels, installed policy and finite "
            "checker limits"
        ],
        "exclusions": [
            "device identity, physical capacity, calibration, sensor accuracy "
            "or live availability as physical facts",
            "authenticity of any observation, quote or event against a trust root",
            "event-log completeness, firmware correctness or event-format conformance",
            "clock authenticity or synchronisation",
            "legacy domain-certificate HARDWARE-3.1 results",
            "whole statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HardwareSubstrateObservationsDescriptor:
    """Native public route metadata for one retained observation proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(
        value, fields, label, HardwareSubstrateObservationsError)


def _retained(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, Refuted)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, HardwareSubstrateObservationsError)


def _bounded_label(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HARDWARE_SUBSTRATE_OBSERVATIONS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=HardwareSubstrateObservationsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def hardware_substrate_observations_policy(
        *, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evaluation_clock", "evaluation_at_us", "evidence_ref",
        "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HARDWARE"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HardwareSubstrateObservationsError(
                "selected substrate observation objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _digest(request[field])
    if not _bounded_label(request["subject_id"]):
        raise HardwareSubstrateObservationsError("bounded subject identifier required")
    if not _bounded_label(request["evaluation_clock"]):
        raise HardwareSubstrateObservationsError("bounded evaluation clock label required")
    instant = request["evaluation_at_us"]
    if type(instant) is not int or not 0 <= instant <= _MAX_INSTANT_US:
        raise HardwareSubstrateObservationsError(
            "evaluation instant must be integer microseconds from 0 through 2^53-1")
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, HardwareSubstrateObservationsError)
    return request


def hardware_substrate_observations_request(
        *, subject_id: str, object_digest: str, collection_digest: str,
        evaluation_clock: str, evaluation_at_us: int, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HardwareSubstrateObservationsError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HARDWARE", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evaluation_clock": evaluation_clock, "evaluation_at_us": evaluation_at_us,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


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


def _instant(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INSTANT_US:
        raise Refuted(label + " must be integer microseconds from 0 through 2^53-1")
    return value


def _claims(value: Any, limits: dict[str, int], budget: common_module.Budget) -> dict[str, bytes]:
    if type(value) is not list:
        raise Refuted("retained claims require a list")
    if not value:
        raise Unavailable("no retained substrate claim; nothing is qualified")
    if len(value) > limits["max_claims"]:
        raise Unavailable("substrate claim bound exhausted")
    claims: dict[str, bytes] = {}
    for row in value:
        budget.tick()
        claim = _retained(row, {"claim_id", "category", "value"}, "substrate claim")
        if not _bounded_label(claim["claim_id"]):
            raise Refuted("bounded claim identifier required")
        if claim["claim_id"] in claims:
            raise Refuted("duplicate substrate claim identifier")
        if type(claim["category"]) is not str or claim["category"] not in CATEGORIES:
            raise Refuted("substrate claim category is not one the governing row names")
        claims[claim["claim_id"]] = canonical_bytes(claim["value"])
    return claims


def _replay(quote: Any, measured_boot: Any, limits: dict[str, int],
            budget: common_module.Budget) -> int:
    """Replay one retained event log by SHA-256 extend to its stated quote."""
    record = _retained(measured_boot, {"events"}, "measured-boot record")
    if type(quote) is not list or not quote:
        raise Refuted("measured-boot record requires a nonempty register quote value")
    registers: dict[int, bytes] = {}
    previous = -1
    for row in quote:
        budget.tick()
        entry = _retained(row, {"register", "value"}, "quoted register")
        register = entry["register"]
        if type(register) is not int or not 0 <= register <= _MAX_REGISTER:
            raise Refuted("quoted register index is unsupported")
        if register <= previous:
            raise Refuted("quoted registers must be strictly increasing")
        if type(entry["value"]) is not str or _HEX64.fullmatch(entry["value"]) is None:
            raise Refuted("quoted register value must be 64 lowercase hexadecimal characters")
        previous = register
        registers[register] = b"\x00" * 32
    events = record["events"]
    if type(events) is not list:
        raise Refuted("measured-boot events require a list")
    if len(events) > limits["max_events"]:
        raise Unavailable("measured-boot event bound exhausted")
    for row in events:
        budget.tick()
        item = _retained(row, {"register", "event", "event_digest"}, "boot event")
        register = item["register"]
        if type(register) is not int or register not in registers:
            raise Refuted("event extends a register outside the stated quote")
        if type(item["event_digest"]) is not str or _HEX64.fullmatch(item["event_digest"]) is None:
            raise Refuted("event digest must be 64 lowercase hexadecimal characters")
        data = _decode_b64(item["event"], "boot event")
        if len(data) > limits["max_event_bytes"]:
            raise Unavailable("measured-boot event byte bound exhausted")
        budget.tick(1 + len(data) // 64)
        if hashlib.sha256(data).hexdigest() != item["event_digest"]:
            raise Refuted("event digest differs from its retained event bytes")
        registers[register] = hashlib.sha256(
            registers[register] + bytes.fromhex(item["event_digest"])).digest()
    for row in quote:
        if registers[row["register"]].hex() != row["value"]:
            raise Refuted("retained event log does not replay to the stated register quote")
    return len(events)


def _evaluate(data: bytes, request: dict[str, Any], roots: tuple[str, ...]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _retained(strict_json_loads(data.decode("utf-8")),
                          {"schema_version", "objects", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _retained(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "HARDWARE"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained hardware subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if value["inputs"] is None:
            raise Unavailable("retained claims and observation records absent")
        inputs = _retained(value["inputs"], {"claims", "observations"}, "substrate inputs")
        payload = _retained(matches[0].payload,
                            {"scope", "claims_digest", "observations_digest"},
                            "hardware payload")
        if payload["scope"] != SUBJECT_SCOPE:
            raise Refuted("hardware record scope differs")
        if (common_module.digest(inputs["claims"]) != payload["claims_digest"]
                or common_module.digest(inputs["observations"]) != payload["observations_digest"]):
            raise Refuted("retained claims or observations differ from the selected record")
        claims = _claims(inputs["claims"], limits, budget)
        observations = inputs["observations"]
        if type(observations) is not list:
            raise Refuted("retained observation records require a list")
        if len(observations) > limits["max_observations"]:
            raise Unavailable("observation record bound exhausted")
        at, clock = request["evaluation_at_us"], request["evaluation_clock"]
        seen: set[str] = set()
        covered: set[str] = set()
        qualified = replayed_events = replayed_records = 0
        for row in observations:
            budget.tick()
            item = _retained(row, {
                "observation_id", "claim_id", "value", "clock", "fresh_from_us",
                "fresh_until_us", "trust_root", "measured_boot",
            }, "observation record")
            if not _bounded_label(item["observation_id"]) or item["observation_id"] in seen:
                raise Refuted("observation identifiers must be bounded and unique")
            seen.add(item["observation_id"])
            if type(item["claim_id"]) is not str or item["claim_id"] not in claims:
                raise Refuted("observation record names no retained claim")
            if not _bounded_label(item["clock"]) or not _bounded_label(item["trust_root"]):
                raise Refuted("observation clock and trust-root labels must be bounded")
            start = _instant(item["fresh_from_us"], "freshness start")
            end = _instant(item["fresh_until_us"], "freshness end")
            if start > end:
                raise Refuted("observation freshness interval is inverted")
            # Internal consistency is time-independent and checked on every record.
            if item["measured_boot"] is not None:
                replayed_events += _replay(item["value"], item["measured_boot"], limits, budget)
                replayed_records += 1
            # Agreement with the declaration is checked only where the record qualifies.
            if item["clock"] == clock and start <= at <= end and item["trust_root"] in roots:
                if canonical_bytes(item["value"]) != claims[item["claim_id"]]:
                    raise Refuted("qualified observation contradicts the declared claim value")
                covered.add(item["claim_id"])
                qualified += 1
        missing = [claim_id for claim_id in claims if claim_id not in covered]
        if missing:
            raise Unavailable(
                "claim rests on declaration alone without a qualified observation: "
                + missing[0])
        return MechanismDecision(
            MechanismOutcome.PASS,
            "every retained claim has a qualified agreeing observation record",
            {"claims": len(claims), "observations": len(observations),
             "qualified_observations": qualified,
             "measured_boot_records": replayed_records,
             "measured_boot_events": replayed_events,
             "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _HardwareSubstrateObservationsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound substrate observation proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained hardware evidence bundle is required")
        return _evaluate(evidence[0], self.request, tuple(self.policy["trust_roots"]))


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HardwareSubstrateObservationsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HardwareSubstrateObservationsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "HARDWARE", "scope": SCOPE,
        _SCOPE_FIELD: ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                       else "NOT_ESTABLISHED"),
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED_FIELDS},
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise HardwareSubstrateObservationsError("certificate byte bound exhausted")
    return encoded


def build_hardware_substrate_observations_certificate(
        request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HardwareSubstrateObservationsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HardwareSubstrateObservationsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_hardware_substrate_observations_certificate(
        certificate_bytes: bytes, *, expected_request: dict[str, Any],
        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HardwareSubstrateObservationsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise HardwareSubstrateObservationsError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HardwareSubstrateObservationsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HardwareSubstrateObservationsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HardwareSubstrateObservationsError):
            raise
        raise HardwareSubstrateObservationsError(
            "invalid retained HARDWARE substrate observation certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SUBJECT_SCOPE", "CATEGORIES",
    "HardwareSubstrateObservationsDescriptor",
    "HardwareSubstrateObservationsError", "registration",
    "hardware_substrate_observations_policy",
    "hardware_substrate_observations_request",
    "build_hardware_substrate_observations_certificate",
    "recheck_hardware_substrate_observations_certificate",
]
