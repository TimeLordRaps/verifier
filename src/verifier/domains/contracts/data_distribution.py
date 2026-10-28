"""Versioned retained DATA distribution certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts and proportions are dimensionless;
entropy and its selected tolerance use bits per retained observation.
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
from verifier.domains import data as data_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "DATA-3.4"
REQUEST_VERSION = "verifier-current-data-distribution-request-1"
POLICY_VERSION = "verifier-current-data-distribution-policy-1"
CERTIFICATE_VERSION = "verifier-current-data-distribution-certificate-1"
EVIDENCE_VERSION = "verifier-current-data-distribution-evidence-1"
MECHANISM_ID = "verifier.current-data.retained-distribution.1"
SCOPE = "finite_retained_exact_value_distribution"
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class DataDistributionError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "DATA", "scope": SCOPE,
        "proposition": (
            "The independently selected exact DATA record occurs in the selected "
            "finite typed collection; its complete retained shard inventory rehashes, "
            "and every selected field has the declared exact canonical-value classes, "
            "counts and entropy within the independently selected numerical tolerance."
        ),
        "prerequisites": [
            "exact DATA record, full finite collection, retained shards, selected "
            "distribution fields, installed policy and finite checker limits"
        ],
        "exclusions": [
            "population representativeness and sampling-frame completeness",
            "external origin, sensor calibration, rights or authenticated authority",
            "whole DATA statics tier or object-profile conformance",
            "privacy, consent, governance, security admission or polished issuance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class DataDistributionDescriptor:
    """Native public route metadata for exact retained-data statistics."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, DataDistributionError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, DataDistributionError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, data_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_DATA_DISTRIBUTION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "entropy_tolerance_bits",
    }, "policy")
    tolerance = selected.pop("entropy_tolerance_bits")
    if type(tolerance) not in (int, float) or not 0 <= tolerance <= 1e-9:
        raise DataDistributionError("finite entropy tolerance from zero through 1e-9 bits required")
    admitted = retained_selection.policy(
        selected, error_type=DataDistributionError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )
    return {**admitted, "entropy_tolerance_bits": tolerance}


def data_distribution_policy(*, trust_roots: list[str], entropy_tolerance_bits: float,
                             max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
        "entropy_tolerance_bits": entropy_tolerance_bits,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, DataDistributionError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "DATA"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise DataDistributionError("selected retained-distribution objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise DataDistributionError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def data_distribution_request(*, subject_id: str, object_digest: str,
                       collection_digest: str, evidence_ref: str,
                       policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise DataDistributionError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "DATA", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
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
        if len(matches) != 1 or matches[0].kind.value != "DATA" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained data subject differs from external selection")
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
            raise Unavailable("retained data shards absent")
        retained = _record(value["inputs"], {"shards"}, "data inputs")
        observed = data_module.distribution(
            matches[0].payload, retained, budget,
            entropy_tolerance_bits=policy["entropy_tolerance_bits"],
        )
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained distribution reproduced",
            {**observed, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _DataDistributionMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound data proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained data evidence bundle is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise DataDistributionError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_DataDistributionMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "DATA", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "external_origin": "NOT_ESTABLISHED",
        "population_representativeness": "NOT_ESTABLISHED",
        "authenticated_authority": "NOT_ESTABLISHED",
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
        raise DataDistributionError("certificate byte bound exhausted")
    return encoded


def build_data_distribution_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                 *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise DataDistributionError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise DataDistributionError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_data_distribution_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise DataDistributionError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise DataDistributionError("canonical certificate version differs")
        if value["request"] != selected:
            raise DataDistributionError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise DataDistributionError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise DataDistributionError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, DataDistributionError):
            raise
        raise DataDistributionError("invalid retained data certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "DataDistributionDescriptor",
    "DataDistributionError", "registration", "data_distribution_policy",
    "data_distribution_request", "build_data_distribution_certificate",
    "recheck_data_distribution_certificate",
]
