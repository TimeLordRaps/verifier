"""Current situated BOT native check certificates. BOT is an object name, not an acronym.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Transcript positions and channel counts are dimensionless.
Retained observations do not establish live execution or physical isolation.
"""
from __future__ import annotations

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
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.namespace import NamespaceObject
from verifier.domains import bot as bot_module
from verifier.domains import certification as domain_certification
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-bot-checks-request-1"
POLICY_VERSION = "verifier-current-bot-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-bot-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-bot-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-bot-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"binding": "BOT-1.6", "alignment": "BOT-2.1", "observation": "BOT-2.2",
          "actuation": "BOT-2.3", "containment": "BOT-4.1"}
_CLAIMS = {
    "binding": "The selected retained agent, simulation, harness and environment records match their actual namespace operands and their native child certificates replay under current external policy.",
    "alignment": "Every retained simulation transition attributed to the selected agent maps to one strictly ordered retained record inside its observation ceiling; exogenous transitions are explicit.",
    "observation": "The retained initial observation and each attributed tool observation equal the selected simulation projections and remain inside the selected agent observation ceiling.",
    "actuation": "Every attributed retained simulation action equals the input of its aligned retained agent tool invocation.",
    "containment": "The selected agent and simulator environments are declared distinct and retain distinct subjects, software inventories and execution identifiers; a fused declaration remains unestablished.",
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise BotChecksError("unsupported bot check")
    return value


def scope(check: str) -> str:
    return "finite_retained_bot_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "BOT", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact BOT record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["actual execution, authentic observations or causal attribution beyond retained correspondence",
                       "physical isolation, simulation effect confinement, actual invocation or model correctness",
                       "historical child-policy reproduction, omitted real-world events or undeclared actions",
                       "unselected objectives, legacy prerequisites, authority or whole tier conformance"]}



def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class BotDescriptor:
    """One exact publicly selectable bot proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class BotChecksError(ValueError):
    """Malformed external selection or substituted bot certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise BotChecksError(label + " fields differ")
    if set(value) != fields:
        raise BotChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise BotChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, bot_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_BOT_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        "direct_sources": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())},
        "native_domain_implementation": domain_certification.implementation_digest()})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes", "max_tolerance"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise BotChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise BotChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise BotChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise BotChecksError("certificate byte bound is unsupported")
    tolerance = policy["max_tolerance"]
    if type(tolerance) not in (int, float) or not 0 <= tolerance <= 1e-4:
        raise BotChecksError("finite checker tolerance outside native supported range")
    policy["trust_roots"] = list(roots)
    return policy


def bot_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES,
                      max_tolerance: float = 0) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "max_tolerance": max_tolerance})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise BotChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "BOT")):
        if type(request[field]) is not str or request[field] != expected:
            raise BotChecksError("selected bot objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise BotChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise BotChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def bot_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise BotChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "BOT", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects", "inputs"}, "evidence")
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
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        records = {item.object_id: item for item in objects}

        def direct(item: NamespaceObject, role: str, kind: str) -> NamespaceObject:
            references = dict(item.operands)[role]
            if len(references) != 1 or records[references[0]].kind.value != kind:
                raise Unavailable("one direct native record per selected bot role is required")
            return records[references[0]]

        selected = {"agent": direct(subject, "agent", "AGENT"),
                    "sim": direct(subject, "sim", "SIM"),
                    "environment": direct(subject, "env", "ENV")}
        selected["agent_environment"] = direct(selected["agent"], "env", "ENV")
        selected["sim_environment"] = direct(selected["sim"], "env", "ENV")
        selected["harness"] = direct(selected["agent"], "harness", "HARNESS")
        selected["agent_model"] = direct(selected["agent"], "model", "MODEL")
        if value["inputs"] is None:
            raise Unavailable("retained native bot inputs are absent")
        retained = common_module.obj(value["inputs"])
        children = ("agent", "sim", "agent_environment", "sim_environment")
        allowed = {name + "_certificate" for name in children} | {"environment", "agent_model"}
        if set(retained) - allowed:
            raise Refuted("unsupported retained bot input")
        for name in ("environment", "agent_model"):
            common_module.same(common_module.need(retained, name), selected[name].payload,
                               "selected " + name + " context differs")
        child_evidence = {}
        for name in children:
            child = common_module.obj(common_module.need(retained, name + "_certificate"))
            evidence = common_module.obj(common_module.need(child, "evidence"))
            common_module.same(common_module.need(evidence, "subject_id"), selected[name].object_id,
                               "child " + name + " subject differs from selected operand")
            common_module.same(common_module.need(evidence, "artifact"), selected[name].payload,
                               "child " + name + " payload differs from selected operand")
            child_evidence[name] = evidence
        agent_inputs = common_module.obj(common_module.need(child_evidence["agent"], "inputs"))
        harness = common_module.obj(common_module.need(agent_inputs, "harness_certificate"))
        harness_evidence = common_module.obj(common_module.need(harness, "evidence"))
        common_module.same(common_module.need(harness_evidence, "subject_id"), selected["harness"].object_id,
                           "nested harness subject differs from selected agent operand")
        common_module.same(common_module.need(harness_evidence, "artifact"), selected["harness"].payload,
                           "nested harness payload differs from selected agent operand")
        child_policy = domain_certification.domain_policy(trust_roots=policy["trust_roots"],
            max_operations=limits["max_operations"], max_items=limits["max_items"],
            max_evidence_bytes=limits["max_evidence_bytes"], max_tolerance=policy["max_tolerance"])
        result = bot_module.evaluate(request["check"], subject.payload, retained, budget,
            mechanism_digest=child_policy["mechanism_digest"], policy=child_policy)
        return MechanismDecision(MechanismOutcome.PASS, "selected retained bot check reproduced",
                                 {"bot": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _BotChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound bot proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained bot evidence bundle is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise BotChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_BotChecksMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": scope(request["check"]),
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise BotChecksError("certificate byte bound exhausted")
    return encoded


def build_bot_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise BotChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise BotChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_bot_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise BotChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise BotChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise BotChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise BotChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise BotChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, BotChecksError):
            raise
        raise BotChecksError("invalid retained bot certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "BotDescriptor", "BotChecksError", "bot_checks_policy",
           "bot_checks_request", "build_bot_checks_certificate", "recheck_bot_checks_certificate"]
