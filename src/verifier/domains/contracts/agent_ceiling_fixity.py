"""Current AGENT-3.1 observation ceiling fixed by bound harness certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Observation ceilings, counts and checker limits
are dimensionless integers.
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
COORDINATE = "AGENT-3.1"
REQUEST_VERSION = "verifier-current-agent-ceiling-fixity-request-1"
POLICY_VERSION = "verifier-current-agent-ceiling-fixity-policy-1"
CERTIFICATE_VERSION = "verifier-current-agent-ceiling-fixity-certificate-1"
EVIDENCE_VERSION = "verifier-current-agent-ceiling-fixity-evidence-1"
MECHANISM_ID = "verifier.current-agent.ceiling-fixity.1"
SCOPE = "exact_agent_record_bound_harness_ceiling"
_PAYLOAD_SCOPE = "retained-agent-ceiling-fixity"
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


class AgentCeilingFixityError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "AGENT",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact AGENT record occurs once in the selected finite "
            "typed collection; its harness operand binds exactly one HARNESS record of that "
            "collection; that HARNESS record states an observation ceiling; and the AGENT "
            "record's declared observation ceiling equals the bound HARNESS record's ceiling "
            "under statics:ceiling, so the only ceiling reported is the harness's."
        ),
        "prerequisites": [
            "independently selected exact AGENT record, finite collection, "
            "retained evidence bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "harness enforcement of the ceiling or what the agent actually observed",
            "AGENT-3.2 unknowability and AGENT-3.3 declaration impotence",
            "memory bounds, guardrails and non-escalation named by the slot rationale",
            "real-world identity of either record, authority, safety, security, privacy or consent",
            "whole AGENT statics tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class AgentCeilingFixityDescriptor:
    """Native public route metadata for one retained agent ceiling fixity proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, AgentCeilingFixityError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, AgentCeilingFixityError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, statics_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_AGENT_CEILING_FIXITY.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=AgentCeilingFixityError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def agent_ceiling_fixity_policy(*, trust_roots: list[str],
                               max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, AgentCeilingFixityError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "AGENT"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise AgentCeilingFixityError("selected agent ceiling objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise AgentCeilingFixityError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def agent_ceiling_fixity_request(*, subject_id: str, object_digest: str,
                                collection_digest: str, evidence_ref: str,
                                policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise AgentCeilingFixityError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "AGENT", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects"}, "evidence")
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
        if len(matches) != 1 or matches[0].kind.value != "AGENT" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained agent subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = _record(matches[0].payload, {"scope", "declared_ceiling"}, "agent payload")
        if payload["scope"] != _PAYLOAD_SCOPE:
            raise Refuted("agent scope differs")
        operands = dict(matches[0].operands)
        harness_ids = operands.get("harness")
        if not harness_ids or len(harness_ids) != 1:
            raise Unavailable("agent harness operand must bind exactly one record")
        harness_id = harness_ids[0]
        harness_matches = [obj for obj in objects if obj.object_id == harness_id]
        if len(harness_matches) != 1 or harness_matches[0].kind.value != "HARNESS":
            raise Unavailable("agent harness operand must bind exactly one HARNESS record")
        harness_payload = harness_matches[0].payload
        if type(harness_payload) is not dict or "observation_ceiling" not in harness_payload:
            raise Unavailable("bound harness observation ceiling absent")
        observation_ceiling = harness_payload["observation_ceiling"]
        artifact: dict[str, Any] = {"harness": observation_ceiling}
        if payload["declared_ceiling"] is not None:
            artifact["declared_ceiling"] = payload["declared_ceiling"]
        evaluation = statics_module.evaluate(
            "AGENT", "ceiling", artifact, {}, budget, subject=request["subject_id"]
        )
        observations = {"harness_id": harness_id, "harness_ceiling": evaluation["ceiling"]}
        return MechanismDecision(
            MechanismOutcome.PASS, "observation ceiling fixed by bound harness",
            observations,
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (Refuted, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _AgentCeilingFixityMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound agent proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained agent evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise AgentCeilingFixityError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_AgentCeilingFixityMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "AGENT",
        "scope": SCOPE,
        "ceiling_fixity": "PASS" if evaluation.outcome.value == "PASS" else "NOT_ESTABLISHED",
        "whole_agent_statics_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "unknowability": "NOT_ESTABLISHED",
        "declaration_impotence": "NOT_ESTABLISHED",
        "harness_enforcement": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "safety": "NOT_ESTABLISHED",
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
        raise AgentCeilingFixityError("certificate byte bound exhausted")
    return encoded


def build_agent_ceiling_fixity_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                          *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise AgentCeilingFixityError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise AgentCeilingFixityError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_agent_ceiling_fixity_certificate(certificate_bytes: bytes, *,
                                            expected_request: dict[str, Any],
                                            policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise AgentCeilingFixityError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise AgentCeilingFixityError("canonical certificate version differs")
        if value["request"] != selected:
            raise AgentCeilingFixityError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise AgentCeilingFixityError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise AgentCeilingFixityError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, AgentCeilingFixityError):
            raise
        raise AgentCeilingFixityError("invalid retained agent ceiling certificate") from exc


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
    "AgentCeilingFixityDescriptor",
    "AgentCeilingFixityError",
    "registration",
    "mechanism_digest",
    "agent_ceiling_fixity_policy",
    "agent_ceiling_fixity_request",
    "build_agent_ceiling_fixity_certificate",
    "recheck_agent_ceiling_fixity_certificate",
]
