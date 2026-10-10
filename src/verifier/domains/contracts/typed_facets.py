"""Current native declared structural-facet certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Declared kind-specific operand structure grants no real-world authority.
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
from verifier.core.namespace import NamespaceObject, ObjectKind, assess_composition
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-typed-facets-request-1"
POLICY_VERSION = "verifier-current-typed-facets-policy-1"
CERTIFICATE_VERSION = "verifier-current-typed-facets-certificate-1"
COLLECTION_VERSION = "verifier-current-typed-facets-collection-1"
MECHANISM_ID = "verifier.current-object.native-declared-facets.1"
SCOPE = "finite_kind_specific_declared_operand_facets"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024,
             "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_PRIMITIVES = frozenset("HUMAN ROLE HARDWARE OBJECT SPACE TIME ENV DATA VERIFIER ARCH HARNESS TOKEN".split())
_CONTRACTS = {
    "ACTOR": "Exactly one HUMAN, AGENT or BOT representation and one responsible HUMAN after typed-graph expansion; a represented HUMAN is its own root.",
    "COLLECTIVE": "Nonempty roles resolving to ROLE leaves.",
    "IDENTITY": "Nonempty actor and role operands resolving respectively to ACTOR and ROLE leaves.",
    "OWNER": "Nonempty actor resolving to ACTOR and object resolving to any admitted kind; ownership eligibility and title are separate.",
    "RECEIPT": "Nonempty subject resolving to any admitted kind and hardware resolving to HARDWARE; issuance and execution are separate.",
    "EVENT": "Nonempty time, space and meaning operands resolving respectively to TIME, SPACE and any admitted kind.",
    "BENCH": "Nonempty verifier and data operands resolving respectively to VERIFIER and DATA.",
    "TRAIN": "Nonempty data, events, bench and arch operands resolving respectively to DATA, EVENT, BENCH and ARCH.",
    "MODEL": "Nonempty train, data, events, bench, arch, env and hardware operands resolving respectively to TRAIN, DATA, EVENT, BENCH, ARCH, ENV and HARDWARE.",
    "AGENT": "Nonempty model, harness and env operands resolving respectively to MODEL, HARNESS and ENV.",
    "SIM": "Nonempty data, verifier, objects and env operands resolving respectively to DATA, VERIFIER, any admitted kind and ENV.",
    "BOT": "Nonempty agent, sim and env operands resolving respectively to AGENT, SIM and ENV.",
    "HYPER": "Named nonempty relational operands resolving to admitted records.",
    "GRAPH": "An admitted declared element_kind and nonempty members; all leaves and intermediate typed graphs preserve the declared kind, with OBJECT admitting any kind.",
}


class TypedFacetsError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def _kind(value: Any) -> str:
    if type(value) is not str or value not in {kind.value for kind in ObjectKind}:
        raise TypedFacetsError("exact admitted object kind required")
    return value


def coordinate(kind: str) -> str:
    return "OBJECT-1.2" if _kind(kind) == "OBJECT" else kind + "-1.1"


def registration(kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    contract = "No composition operands; kind-specific payload meaning is not checked." if kind in _PRIMITIVES else _CONTRACTS[kind]
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind), "subject_kind": kind, "scope": SCOPE,
        "proposition": "The externally selected exact " + kind + " record occurs in the selected finite collection, every retained namespace record reconstructs exactly, all declared references resolve, composition is acyclic, and each record satisfies its declared kind's operand contract. " + contract,
        "prerequisites": ["externally selected subject, complete collection commitment, evidence and installed policy"],
        "exclusions": ["payload truth or domain-specific payload completeness", "actual personhood or legal identity", "execution or issuance", "ownership eligibility or title", "physical containment", "privacy, consent, governance or authority", "whole tier or object-profile conformance"]}


@dataclass(frozen=True)
class FacetDescriptor:
    """Immutable kind-specific public registration metadata."""
    kind: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return "sha256:" + canonical_digest(registration(self.kind))


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise TypedFacetsError(label + " fields differ")
    if set(value) != fields:
        raise TypedFacetsError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise TypedFacetsError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TYPED_FACETS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise TypedFacetsError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise TypedFacetsError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise TypedFacetsError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise TypedFacetsError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def typed_facets_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise TypedFacetsError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    kind = _kind(request["object_kind"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION), ("coordinate", coordinate(kind))):
        if type(request[field]) is not str or request[field] != expected:
            raise TypedFacetsError("selected native facet objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != FacetDescriptor(kind).PROPOSITION_DIGEST:
        raise TypedFacetsError("selected proposition differs")
    subject = request["subject_id"]
    if type(subject) is not str or not subject.strip() or len(subject) > 256:
        raise TypedFacetsError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def typed_facets_request(*, object_kind: str, subject_id: str, object_digest: str,
                         collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise TypedFacetsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(object_kind), "proposition_digest": FacetDescriptor(object_kind).PROPOSITION_DIGEST,
        "object_kind": object_kind, "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects"}, "collection")
        if value["schema_version"] != COLLECTION_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained collection version or canonical bytes differ")
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
        if len(matches) != 1 or matches[0].kind.value != request["object_kind"] or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        result = assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        return MechanismDecision(MechanismOutcome(result.verdict.value), result.reason,
            {"collection_digest": result.collection_digest, "objects_checked": result.objects_checked})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _TypedFacetsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound native proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained collection is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TypedFacetsError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_TypedFacetsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "payload_semantics": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise TypedFacetsError("certificate byte bound exhausted")
    return encoded


def build_typed_facets_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise TypedFacetsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TypedFacetsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_typed_facets_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TypedFacetsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise TypedFacetsError("canonical certificate version differs")
        if value["request"] != selected:
            raise TypedFacetsError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise TypedFacetsError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TypedFacetsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TypedFacetsError):
            raise
        raise TypedFacetsError("invalid native facet certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CERTIFICATE_VERSION", "COLLECTION_VERSION", "SCOPE", "TypedFacetsError",
           "coordinate", "registration", "typed_facets_policy", "typed_facets_request",
           "build_typed_facets_certificate", "recheck_typed_facets_certificate"]
