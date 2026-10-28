"""Current declared identity role and scope admission certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Declared role membership and scope admission grant no real-world authority.
"""
from __future__ import annotations

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
from verifier.domains.contracts import identity_occupancy
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-identity-scope-request-1"
POLICY_VERSION = "verifier-current-identity-scope-policy-1"
CERTIFICATE_VERSION = "verifier-current-identity-scope-certificate-1"
EVIDENCE_VERSION = "verifier-current-identity-scope-evidence-1"
MECHANISM_ID = "verifier.current-object.identity-role-scope.1"
SCOPE = "finite_declared_identity_role_scope_admission"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_relation_steps": 100000,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024,
             "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
COORDINATE = "IDENTITY-3.1"
PROPOSITION = {
    "schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE, "subject_kind": "IDENTITY", "scope": SCOPE,
    "proposition": "The externally selected exact IDENTITY record and retained declaration agree on one ACTOR, represented HUMAN/AGENT/BOT, responsible HUMAN, one ROLE in the selected COLLECTIVE, and a scope admitted by that ROLE; a BOT scope names one bound SIM. The exact finite collection satisfies declared typed composition.",
    "prerequisites": ["independently selected subject, collective, declaration, collection, evidence, installed policy and finite limits"],
    "exclusions": ["actual personhood or human authentication", "live occupancy", "role authority or consent", "resolution of the declaration evidence locator", "privacy, governance, security or computational correctness", "whole statics tier or object-profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(PROPOSITION)


class IdentityScopeError(ValueError):
    """Malformed external selection or substituted identity certificate."""


class IdentityScopeUnavailable(OSError):
    """Retained checking capacity is unavailable; no semantic refusal."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise IdentityScopeError(label + " fields differ")
    if set(value) != fields:
        raise IdentityScopeError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise IdentityScopeError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, identity_occupancy)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "IDENTITY_OCCUPANCY.md", "CURRENT_IDENTITY_SCOPE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise IdentityScopeError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise IdentityScopeError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise IdentityScopeError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise IdentityScopeError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def identity_scope_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise IdentityScopeError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "object_kind", "subject_id", "object_digest", "collective_id", "declaration_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE), ("object_kind", "IDENTITY")):
        if type(request[field]) is not str or request[field] != expected:
            raise IdentityScopeError("selected identity objective differs")
    for field in ("proposition_digest", "object_digest", "declaration_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != PROPOSITION_DIGEST:
        raise IdentityScopeError("selected proposition differs")
    for field in ("subject_id", "collective_id"):
        value = request[field]
        if type(value) is not str or not value.strip() or len(value) > 256:
            raise IdentityScopeError("bounded subject and collective identifiers required")
    request["limits"] = _limits(request["limits"])
    return request


def identity_scope_request(*, subject_id: str, object_digest: str, collective_id: str,
                           declaration_digest: str, collection_digest: str, evidence_ref: str,
                           policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise IdentityScopeError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "IDENTITY", "subject_id": subject_id, "object_digest": object_digest,
        "collective_id": collective_id, "declaration_digest": declaration_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects", "declaration"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
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
        if len(matches) != 1 or matches[0].kind.value != "IDENTITY" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        result = identity_occupancy.assess_identity_occupancy(objects,
            identity_id=request["subject_id"], collective_id=request["collective_id"],
            expected_digest=request["collection_digest"], expected_evidence_digest=request["declaration_digest"],
            evidence=value["declaration"], max_objects=limits["max_objects"],
            max_operations=limits["max_operations"], max_relation_steps=limits["max_relation_steps"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        return MechanismDecision(MechanismOutcome(result["status"]), result["reason"],
            {"identity_assessment": result})
    except (RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc),
            {"checking_resource_unavailable": True})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "collective_id", "declaration_digest", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _IdentityScopeMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound identity proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained identity evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise IdentityScopeError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_IdentityScopeMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise IdentityScopeError("certificate byte bound exhausted")
    return encoded


def build_identity_scope_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise IdentityScopeError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise IdentityScopeError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def _carried_selection_boundary(value: dict[str, Any], request: dict[str, Any], policy: dict[str, Any]) -> None:
    """Refuse independently decidable envelope/result contradictions before replay."""
    if (value["policy_digest"] != request["policy_digest"]
            or value["mechanism_digest"] != policy["mechanism_digest"]
            or value["proposition_digest"] != request["proposition_digest"]
            or value["evidence_refs"] != [request["evidence_ref"]]
            or value["digest"] != "sha256:" + canonical_digest({k:v for k,v in value.items() if k != "digest"})):
        raise IdentityScopeError("retained envelope differs from exact independent bindings")
    result = _record(value["result"], {"status", "semantic_version", "coordinate", "object_kind",
        "scope", "object_profile_conformance", "authority", "evaluation"}, "result")
    if (type(result["status"]) is not str or result["status"] not in ("PASS", "FAIL", "UNKNOWN")
            or result["semantic_version"] != SEMANTIC_VERSION or result["coordinate"] != request["coordinate"]
            or result["object_kind"] != "IDENTITY" or result["scope"] != SCOPE
            or result["object_profile_conformance"] != "NOT_ESTABLISHED" or result["authority"] != "NOT_ESTABLISHED"):
        raise IdentityScopeError("retained result exceeds its selected native claim boundary")
    evaluated = _record(result["evaluation"], {"binding_digest", "outcome", "mechanism_id", "mechanism_digest",
        "evidence_refs", "trust_roots", "observed_evidence_bytes", "details", "observations"}, "evaluation")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    if (evaluated["binding_digest"] != binding.digest() or evaluated["outcome"] != result["status"]
            or evaluated["mechanism_id"] != MECHANISM_ID or evaluated["mechanism_digest"] != policy["mechanism_digest"]
            or evaluated["evidence_refs"] != [request["evidence_ref"]] or evaluated["trust_roots"] != policy["trust_roots"]
            or type(evaluated["observed_evidence_bytes"]) is not int or evaluated["observed_evidence_bytes"] < 0
            or type(evaluated["details"]) is not str or type(evaluated["observations"]) is not dict):
        raise IdentityScopeError("retained evaluation differs from exact independent proposition")


def recheck_identity_scope_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise IdentityScopeError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise IdentityScopeError("canonical certificate version differs")
        if value["request"] != selected:
            raise IdentityScopeError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise IdentityScopeError("retained evidence differs")
        _carried_selection_boundary(value, selected, admitted)
        store = EvidenceStore(); store.import_base64(payloads)
        observed_bytes = len(store.resolve(selected["evidence_ref"])) if selected["evidence_ref"] in store else 0
        if value["result"]["evaluation"]["observed_evidence_bytes"] != observed_bytes:
            raise IdentityScopeError("retained observed evidence byte count differs from exact imported bytes")
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            current = strict_json_loads(rebuilt.decode("utf-8"))["result"]
            if (current["status"] == "UNKNOWN" and
                    current["evaluation"]["observations"].get("checking_resource_unavailable") is True):
                raise IdentityScopeUnavailable("native evidence replay capacity unavailable; retained result not reproduced")
            raise IdentityScopeError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise IdentityScopeUnavailable("retained certificate checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, IdentityScopeError):
            raise
        raise IdentityScopeError("invalid identity scope certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "SCOPE",
           "PROPOSITION", "PROPOSITION_DIGEST", "IdentityScopeError", "IdentityScopeUnavailable", "identity_scope_policy",
           "identity_scope_request", "build_identity_scope_certificate", "recheck_identity_scope_certificate"]
