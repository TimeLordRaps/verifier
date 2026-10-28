"""Current BOT-3.1 observation ceiling inherited through bound agent certificate.

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
COORDINATE = "BOT-3.1"
REQUEST_VERSION = "verifier-current-bot-inherited-ceiling-request-1"
POLICY_VERSION = "verifier-current-bot-inherited-ceiling-policy-1"
CERTIFICATE_VERSION = "verifier-current-bot-inherited-ceiling-certificate-1"
EVIDENCE_VERSION = "verifier-current-bot-inherited-ceiling-evidence-1"
MECHANISM_ID = "verifier.current-bot.inherited-ceiling.1"
SCOPE = "exact_bot_record_inherited_harness_ceiling"
_PAYLOAD_SCOPE = "retained-bot-inherited-ceiling"
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


class BotInheritedCeilingError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "BOT",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact BOT record occurs once in the selected finite "
            "typed collection. Its agent operand binds exactly one AGENT record, and that "
            "record's harness operand binds exactly one HARNESS record. That HARNESS "
            "record states an integer observation ceiling. The ceiling is reported from "
            "that record, whether the bot or the agent claims a ceiling, claims none, or "
            "claims a different one. A present claim that exceeds it is refuted under "
            "statics:inherited."
        ),
        "prerequisites": [
            "independently selected exact BOT record, finite collection, "
            "retained evidence bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "harness enforcement of the ceiling or what the bot actually observed",
            "BOT-3.2 coupling latency, BOT-3.3 disclosure limit and BOT-3.4 policy impotence",
            "execution quotas, capability whitelists and operation budgets named by the slot rationale",
            "real-world identity of any record, authority, safety, security, privacy or consent",
            "whole BOT statics tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class BotInheritedCeilingDescriptor:
    """Native public route metadata for one retained bot inherited ceiling proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, BotInheritedCeilingError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, BotInheritedCeilingError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, statics_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_BOT_INHERITED_CEILING.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=BotInheritedCeilingError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def bot_inherited_ceiling_policy(*, trust_roots: list[str],
                                max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, BotInheritedCeilingError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "BOT"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise BotInheritedCeilingError("selected bot ceiling objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise BotInheritedCeilingError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def bot_inherited_ceiling_request(*, subject_id: str, object_digest: str,
                                 collection_digest: str, evidence_ref: str,
                                 policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise BotInheritedCeilingError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "BOT", "subject_id": subject_id,
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
        if len(matches) != 1 or matches[0].kind.value != "BOT" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained bot subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = _record(matches[0].payload, {"scope", "claimed_ceiling"}, "bot payload")
        if payload["scope"] != _PAYLOAD_SCOPE:
            raise Refuted("bot scope differs")
        operands = dict(matches[0].operands)
        agent_ids = operands.get("agent")
        if not agent_ids or len(agent_ids) != 1:
            raise Unavailable("bot agent operand must bind exactly one record")
        agent_id = agent_ids[0]
        agent_matches = [obj for obj in objects if obj.object_id == agent_id]
        if len(agent_matches) != 1 or agent_matches[0].kind.value != "AGENT":
            raise Unavailable("bot agent operand must bind exactly one AGENT record")
        agent_obj = agent_matches[0]
        agent_operands = dict(agent_obj.operands)
        harness_ids = agent_operands.get("harness")
        if not harness_ids or len(harness_ids) != 1:
            raise Unavailable("agent harness operand must bind exactly one record")
        harness_id = harness_ids[0]
        harness_matches = [obj for obj in objects if obj.object_id == harness_id]
        if len(harness_matches) != 1 or harness_matches[0].kind.value != "HARNESS":
            raise Unavailable("agent harness operand must bind exactly one HARNESS record")
        harness_payload = harness_matches[0].payload
        if type(harness_payload) is not dict or "observation_ceiling" not in harness_payload:
            raise Unavailable("bound harness observation ceiling absent")
        obs_ceiling = harness_payload["observation_ceiling"]
        obs_obj = common_module.obj(obs_ceiling, {"ceiling", "observed"})
        inherited = common_module.integer(obs_obj["ceiling"])
        claims = [c for c in (payload["claimed_ceiling"], agent_obj.payload.get("declared_ceiling")) if c is not None]
        for claim in claims:
            statics_module.evaluate(
                "BOT", "inherited",
                {"agent": {"claimed_ceiling": claim, "harness_ceiling": inherited}},
                {}, budget, subject=request["subject_id"]
            )
        observations = {
            "agent_id": agent_id,
            "harness_id": harness_id,
            "inherited_ceiling": inherited,
            "claims_checked": len(claims),
        }
        return MechanismDecision(
            MechanismOutcome.PASS, "observation ceiling inherited through bound agent",
            observations,
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (Refuted, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _BotInheritedCeilingMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound bot proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained bot evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise BotInheritedCeilingError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_BotInheritedCeilingMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "BOT",
        "scope": SCOPE,
        "inherited_ceiling": "PASS" if evaluation.outcome.value == "PASS" else "NOT_ESTABLISHED",
        "whole_bot_statics_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "coupling_latency": "NOT_ESTABLISHED",
        "disclosure_limit": "NOT_ESTABLISHED",
        "policy_impotence": "NOT_ESTABLISHED",
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
        raise BotInheritedCeilingError("certificate byte bound exhausted")
    return encoded


def build_bot_inherited_ceiling_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                           *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise BotInheritedCeilingError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise BotInheritedCeilingError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_bot_inherited_ceiling_certificate(certificate_bytes: bytes, *,
                                             expected_request: dict[str, Any],
                                             policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise BotInheritedCeilingError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise BotInheritedCeilingError("canonical certificate version differs")
        if value["request"] != selected:
            raise BotInheritedCeilingError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise BotInheritedCeilingError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise BotInheritedCeilingError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, BotInheritedCeilingError):
            raise
        raise BotInheritedCeilingError("invalid retained bot inherited ceiling certificate") from exc


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
    "BotInheritedCeilingDescriptor",
    "BotInheritedCeilingError",
    "registration",
    "mechanism_digest",
    "bot_inherited_ceiling_policy",
    "bot_inherited_ceiling_request",
    "build_bot_inherited_ceiling_certificate",
    "recheck_bot_inherited_ceiling_certificate",
]
