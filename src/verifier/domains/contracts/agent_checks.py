"""Current agent trajectory (AGENT) native check certificates.

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
from verifier.domains import agent as agent_module
from verifier.domains import certification as domain_certification
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-agent-checks-request-1"
POLICY_VERSION = "verifier-current-agent-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-agent-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-agent-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-agent-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"harness": "AGENT-1.8", "trajectory": "AGENT-2.1", "actions": "AGENT-2.3",
          "outcomes": "AGENT-4.1", "claims": "AGENT-4.3"}
_CLAIMS = {
    "harness": "The exact selected retained harness certificate is semantically replayed under the current external policy; required channels are inside its instrumented observation surface.",
    "trajectory": "Every retained declared decision has its exact contiguous integer position and references a record inside the bound observation ceiling.",
    "actions": "Every distinct declared action references exactly one matching retained tool invocation inside the observation ceiling.",
    "outcomes": "The complete retained outcome inventory equals the selected declared outcome contract, preserving canonical value types.",
    "claims": "Every uniquely identified declared claim references distinct records inside the observation ceiling, and its distinct declared channels equal the channels of those supporting records.",
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise AgentChecksError("unsupported agent check")
    return value


def scope(check: str) -> str:
    return "finite_retained_agent_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "AGENT", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact AGENT record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["actual execution, authentic observation, internal deliberation or causal decision attribution",
                       "model correctness, tool functionality, statement truth or semantic entailment",
                       "historical child-policy reproduction, omitted real-world events or undeclared actions",
                       "unselected objectives, legacy prerequisites, authority or whole tier conformance"]}



def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class AgentDescriptor:
    """One exact publicly selectable agent proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class AgentChecksError(ValueError):
    """Malformed external selection or substituted agent certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise AgentChecksError(label + " fields differ")
    if set(value) != fields:
        raise AgentChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise AgentChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, agent_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_AGENT_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        "direct_sources": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())},
        "native_domain_implementation": domain_certification.implementation_digest()})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise AgentChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise AgentChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise AgentChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise AgentChecksError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def agent_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise AgentChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "AGENT")):
        if type(request[field]) is not str or request[field] != expected:
            raise AgentChecksError("selected agent objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise AgentChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise AgentChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def agent_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise AgentChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "AGENT", "subject_id": subject_id, "object_digest": object_digest,
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
        if len(matches) != 1 or matches[0].kind.value != "AGENT" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        operands = dict(subject.operands)
        records = {item.object_id: item for item in objects}
        kinds = {"model": "MODEL", "harness": "HARNESS", "env": "ENV"}
        if any(len(operands[role]) != 1 or records[operands[role][0]].kind.value != kind for role, kind in kinds.items()):
            raise Unavailable("one direct native record per selected agent role is required")
        selected = {role: records[operands[role][0]] for role in kinds}
        if value["inputs"] is None:
            raise Unavailable("retained native agent inputs are absent")
        retained = common_module.obj(value["inputs"])
        if set(retained) - {"harness_certificate", "steps", "actions", "outcomes", "model", "environment"}:
            raise Refuted("unsupported retained agent input")
        common_module.same(common_module.need(retained, "model"), selected["model"].payload,
                           "selected model context differs")
        common_module.same(common_module.need(retained, "environment"), selected["env"].payload,
                           "selected environment context differs")
        child = common_module.obj(common_module.need(retained, "harness_certificate"))
        child_evidence = common_module.obj(common_module.need(child, "evidence"))
        common_module.same(common_module.need(child_evidence, "subject_id"), selected["harness"].object_id,
                           "child harness subject differs from selected operand")
        common_module.same(common_module.need(subject.payload, "harness_subject_id"), selected["harness"].object_id,
                           "agent harness subject differs from selected operand")
        common_module.same(common_module.need(child_evidence, "artifact"), selected["harness"].payload,
                           "child harness payload differs from selected operand")
        child_policy = domain_certification.domain_policy(trust_roots=policy["trust_roots"],
            max_operations=limits["max_operations"], max_items=limits["max_items"],
            max_evidence_bytes=limits["max_evidence_bytes"], max_tolerance=0)
        result = agent_module.evaluate(request["check"], subject.payload, retained, budget,
            mechanism_digest=child_policy["mechanism_digest"], policy=child_policy)
        if request["check"] == "actions":
            actions = common_module.seq(common_module.need(retained, "actions"), budget, nonempty=False)
            pairs = [(action["tool"], action["record"]) for action in actions]
            if len(pairs) != len(set(pairs)):
                raise Refuted("duplicate declared action")
            child_inputs = common_module.obj(common_module.need(child_evidence, "inputs"))
            invocations = common_module.seq(common_module.need(child_inputs, "invocations"), budget, nonempty=False)
            counts: dict[tuple[str, int], int] = {}
            for invocation in invocations:
                pair = (invocation["tool"], invocation["index"])
                counts[pair] = counts.get(pair, 0) + 1
            if any(counts.get(pair) != 1 for pair in pairs):
                raise Refuted("declared action requires exactly one retained invocation")
        elif request["check"] == "claims":
            claims = common_module.seq(common_module.need(subject.payload, "claims"), budget)
            child_inputs = common_module.obj(common_module.need(child_evidence, "inputs"))
            transcript = common_module.seq(common_module.need(child_inputs, "records"), budget)
            common_module.unique(claims, "id")
            for claim in claims:
                support, channels = claim["support"], claim["channels"]
                budget.tick(len(support) + len(channels))
                if len(support) != len(set(support)) or len(channels) != len(set(channels)):
                    raise Refuted("claim support and channels must be distinct")
                actual = sorted({transcript[index]["channel"] for index in support})
                common_module.same(sorted(channels), actual, "claim channels differ from supporting records")
        return MechanismDecision(MechanismOutcome.PASS, "selected retained agent check reproduced",
                                 {"agent": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _AgentChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound agent proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained agent evidence bundle is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise AgentChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_AgentChecksMechanism(request, policy))
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
        raise AgentChecksError("certificate byte bound exhausted")
    return encoded


def build_agent_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise AgentChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise AgentChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_agent_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise AgentChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise AgentChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise AgentChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise AgentChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise AgentChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, AgentChecksError):
            raise
        raise AgentChecksError("invalid retained agent certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "AgentDescriptor", "AgentChecksError", "agent_checks_policy",
           "agent_checks_request", "build_agent_checks_certificate", "recheck_agent_checks_certificate"]
