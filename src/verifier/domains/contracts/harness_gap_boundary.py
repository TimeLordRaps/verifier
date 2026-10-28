"""Current HARNESS-3.1 named gaps bounded by retained instrument placements certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Window, placement and gap endpoints are integer
instants of one declared session clock; intervals are half-open; counts are
dimensionless.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
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
from verifier.domains import statics as statics_module
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HARNESS-3.1"
REQUEST_VERSION = "verifier-current-harness-gap-boundary-request-1"
POLICY_VERSION = "verifier-current-harness-gap-boundary-policy-1"
CERTIFICATE_VERSION = "verifier-current-harness-gap-boundary-certificate-1"
EVIDENCE_VERSION = "verifier-current-harness-gap-boundary-evidence-1"
MECHANISM_ID = "verifier.current-harness.gap-boundary.1"
SCOPE = "exact_harness_record_retained_instrument_placements"
_PAYLOAD_SCOPE = "retained-harness-gap-boundary"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class HarnessGapBoundaryError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "HARNESS",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact HARNESS record occurs once in the selected finite "
            "typed collection. Its retained named instrument placements rehash to its commitment "
            "and lie inside its declared session window. Under statics:gap, its declared named "
            "gaps equal, in ascending order, the complement of those placements over the window. "
            "Each gap therefore begins at the window start or where a named placement ends, "
            "and ends at the window end or where a named placement begins."
        ),
        "prerequisites": [
            "independently selected exact HARNESS record, finite collection, "
            "retained placements, installed policy and finite checker limits"
        ],
        "exclusions": [
            "that any instrument was actually placed, or what happened inside a gap",
            "clock accuracy, HARNESS-3.2 timestamp resolution, HARNESS-3.3 channel capacity and HARNESS-3.4 instrument fixity",
            "isolation, interceptor determinism and immutable test logic named by the slot rationale",
            "authority, safety, security, privacy or consent",
            "whole HARNESS statics tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HarnessGapBoundaryDescriptor:
    """Native public route metadata for one retained harness gap boundary proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, HarnessGapBoundaryError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, HarnessGapBoundaryError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, statics_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HARNESS_GAP_BOUNDARY.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=HarnessGapBoundaryError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def harness_gap_boundary_policy(*, trust_roots: list[str],
                               max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, HarnessGapBoundaryError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HARNESS"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HarnessGapBoundaryError("selected harness gap objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise HarnessGapBoundaryError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def harness_gap_boundary_request(*, subject_id: str, object_digest: str,
                                collection_digest: str, evidence_ref: str,
                                policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HarnessGapBoundaryError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HARNESS", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
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
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if len(matches) != 1 or matches[0].kind.value != "HARNESS" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained harness subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = _record(matches[0].payload, {"scope", "window", "gaps", "placements_digest"}, "harness payload")
        if payload["scope"] != _PAYLOAD_SCOPE:
            raise Refuted("harness scope differs")
        commitment = _hash(payload["placements_digest"])

        if value["inputs"] is None:
            raise Unavailable("retained placements absent")
        inputs = _record(value["inputs"], {"placements"}, "harness inputs")
        if inputs["placements"] is None:
            raise Unavailable("retained placements absent")
        placements = inputs["placements"]
        if type(placements) is not list:
            raise Refuted("placements must be a list")
        if commitment != "sha256:" + canonical_digest(placements):
            raise Refuted("retained placements commitment differs")

        window = _record(payload["window"], {"start", "end"}, "window")
        window_start = common_module.integer(window["start"])
        window_end = common_module.integer(window["end"])
        if window_end <= window_start:
            raise Refuted("window start must precede window end")

        gaps = payload["gaps"]
        if type(gaps) is not list:
            raise Refuted("gaps must be a list")
        gap_names: set[str] = set()
        for gap in gaps:
            budget.tick()
            g_rec = _record(gap, {"name", "start", "end"}, "gap")
            g_name = g_rec["name"]
            if type(g_name) is not str or not g_name.strip() or len(g_name) > 256:
                raise Refuted("gap name must be a nonempty bounded string")
            if g_name in gap_names:
                raise Refuted("duplicate gap name")
            gap_names.add(g_name)
            common_module.integer(g_rec["start"])
            common_module.integer(g_rec["end"])

        for p in placements:
            budget.tick()
            p_rec = _record(p, {"instrument", "start", "end"}, "placement")
            p_inst = p_rec["instrument"]
            if type(p_inst) is not str or not p_inst.strip() or len(p_inst) > 256:
                raise Refuted("placement instrument must be a nonempty bounded string")
            common_module.integer(p_rec["start"])
            common_module.integer(p_rec["end"])

        artifact = {
            "window": window,
            "gap": [{"start": g["start"], "end": g["end"]} for g in gaps],
        }
        inputs_dict = {
            "instrumented": [{"start": p["start"], "end": p["end"]} for p in placements],
        }
        evaluation = statics_module.evaluate(
            "HARNESS", "gap", artifact, inputs_dict, budget, subject=request["subject_id"]
        )

        anchored = []
        for g in gaps:
            budget.tick(len(placements))
            g_start, g_end = g["start"], g["end"]
            if g_start == window_start:
                after = None
            else:
                after_matches = sorted({p["instrument"] for p in placements if p["end"] == g_start})
                if not after_matches:
                    raise Refuted(f"gap {g['name']} has no placement anchor ending at start")
                after = after_matches
            if g_end == window_end:
                before = None
            else:
                before_matches = sorted({p["instrument"] for p in placements if p["start"] == g_end})
                if not before_matches:
                    raise Refuted(f"gap {g['name']} has no placement anchor starting at end")
                before = before_matches
            anchored.append({
                "name": g["name"],
                "start": g_start,
                "end": g_end,
                "after": after,
                "before": before,
            })

        observations = {
            "placements": len(placements),
            "uninstrumented": evaluation["uninstrumented"],
            "gaps": anchored,
        }
        return MechanismDecision(
            MechanismOutcome.PASS, "named gaps bounded by instrument placements",
            observations,
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (Refuted, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _HarnessGapBoundaryMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound harness proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained harness evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HarnessGapBoundaryError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HarnessGapBoundaryMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "HARNESS",
        "scope": SCOPE,
        "gap_boundary": "PASS" if evaluation.outcome.value == "PASS" else "NOT_ESTABLISHED",
        "whole_harness_statics_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "timestamp_resolution": "NOT_ESTABLISHED",
        "channel_capacity": "NOT_ESTABLISHED",
        "instrument_fixity": "NOT_ESTABLISHED",
        "actual_instrument_placement": "NOT_ESTABLISHED",
        "isolation": "NOT_ESTABLISHED",
        "security": "NOT_ESTABLISHED",
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
        raise HarnessGapBoundaryError("certificate byte bound exhausted")
    return encoded


def build_harness_gap_boundary_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                          *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HarnessGapBoundaryError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HarnessGapBoundaryError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_harness_gap_boundary_certificate(certificate_bytes: bytes, *,
                                            expected_request: dict[str, Any],
                                            policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HarnessGapBoundaryError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise HarnessGapBoundaryError("canonical certificate version differs")
        if value["request"] != selected:
            raise HarnessGapBoundaryError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HarnessGapBoundaryError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HarnessGapBoundaryError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HarnessGapBoundaryError):
            raise
        raise HarnessGapBoundaryError("invalid retained harness gap certificate") from exc


__all__ = [
    "SEMANTIC_VERSION",
    "COORDINATE",
    "REQUEST_VERSION",
    "POLICY_VERSION",
    "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION",
    "MECHANISM_ID",
    "SCOPE",
    "PROPOSITION_DIGEST",
    "HarnessGapBoundaryDescriptor",
    "HarnessGapBoundaryError",
    "registration",
    "mechanism_digest",
    "harness_gap_boundary_policy",
    "harness_gap_boundary_request",
    "build_harness_gap_boundary_certificate",
    "recheck_harness_gap_boundary_certificate",
]
