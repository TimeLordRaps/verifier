"""Current bounded full-record disclosure certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Declared kind-specific operand structure grants no real-world authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
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
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.privacy import engine as privacy_engine
from verifier.privacy import models as privacy_models
from verifier.privacy import composition as privacy_composition
from verifier.privacy import independence as privacy_independence
from verifier.privacy import adapters as privacy_adapters

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-privacy-checks-request-1"
POLICY_VERSION = "verifier-current-privacy-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-privacy-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-privacy-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.full-record-disclosure.1"
SCOPE = "finite_full_record_disclosure_under_declared_bounds"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024,
             "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class PrivacyChecksError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def _kind(value: Any) -> str:
    if type(value) is not str or value not in {kind.value for kind in ObjectKind}:
        raise PrivacyChecksError("exact admitted object kind required")
    return value


def coordinate(kind: str) -> str:
    return _kind(kind) + "-6.7"


def registration(kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind), "subject_kind": kind, "scope": SCOPE,
        "proposition": "The externally selected exact " + kind + " namespace record is structurally admitted in its bound collection; its complete canonical record is unchanged by the native disclosure evaluator under independently selected field enumeration, declarative bounds and observer facts, and its selected co-disclosures trigger no bundled or additional typed refusal rule.",
        "prerequisites": ["externally selected subject, collection, evidence, disclosure policy and context label"],
        "exclusions": ["observer authentication or permission to transmit", "general composition privacy", "underlying payload or certificate validity", "hiding or zero-knowledge proof", "actual emission or trusted time", "consent, governance or authority", "whole tier or object-profile conformance"]}


@dataclass(frozen=True)
class PrivacyDescriptor:
    """Immutable kind-specific disclosure registration metadata."""
    kind: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return "sha256:" + canonical_digest(registration(self.kind))


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise PrivacyChecksError(label + " fields differ")
    if set(value) != fields:
        raise PrivacyChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise PrivacyChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module,
               privacy_engine, privacy_models, privacy_composition, privacy_independence, privacy_adapters)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_PRIVACY_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _capture(value: Any) -> Any:
    """Bound and copy plain policy values before hashing or native callbacks."""
    nodes = text_bytes = 0
    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > 50000 or depth > 64:
            raise PrivacyChecksError("selection structural bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > 1024 * 1024:
                raise PrivacyChecksError("selection text bound exhausted")
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > 1024 * 1024:
                raise PrivacyChecksError("selection text bound exhausted")
            return item
        if item is None or kind is bool:
            return item
        if kind is int and item.bit_length() <= 4096:
            return item
        if kind is float and math.isfinite(item):
            return item
        if kind is dict:
            if len(item) > 4096 or any(type(key) is not str for key in item):
                raise PrivacyChecksError("selection mapping is unsupported")
            return {visit(key, depth + 1): visit(child, depth + 1) for key, child in item.items()}
        if kind is list:
            if len(item) > 4096:
                raise PrivacyChecksError("selection array bound exhausted")
            return [visit(child, depth + 1) for child in item]
        raise PrivacyChecksError("selection requires bounded plain finite values")
    try:
        return visit(value, 0)
    except (UnicodeError, RuntimeError, RecursionError) as exc:
        raise PrivacyChecksError("selection cannot be captured") from exc


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise PrivacyChecksError("bounded nonempty selection text required")
    return value


def _strings(value: Any) -> list[str]:
    if type(value) is not list or len(value) > 64:
        raise PrivacyChecksError("bounded selection string array required")
    result = [_text(item) for item in value]
    if len(set(result)) != len(result):
        raise PrivacyChecksError("duplicate selection names are unsupported")
    return result


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(_capture(value), {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes", "observer", "disclosed_fields", "withheld_fields", "bounds", "co_emitted_ids", "extra_join_rules"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise PrivacyChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise PrivacyChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise PrivacyChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise PrivacyChecksError("certificate byte bound is unsupported")
    observer = _record(policy["observer"], {"actor_id", "role", "purpose", "credentials"}, "observer")
    for name in ("actor_id", "role", "purpose"):
        _text(observer[name])
    _strings(observer["credentials"])
    for name in ("disclosed_fields", "withheld_fields", "co_emitted_ids"):
        _strings(policy[name])
    bounds = policy["bounds"]
    if type(bounds) is not list or len(bounds) > 256:
        raise PrivacyChecksError("bounded declarative field bounds required")
    identifiers = set()
    for row in bounds:
        bound = _record(row, {"bound_id", "field_name", "admitted_observers", "admitted_roles", "conditions"}, "bound")
        identifier = _text(bound["bound_id"])
        if identifier in identifiers:
            raise PrivacyChecksError("duplicate disclosure bound identifier")
        identifiers.add(identifier); _text(bound["field_name"])
        _strings(bound["admitted_observers"]); _strings(bound["admitted_roles"])
        conditions = bound["conditions"]
        if type(conditions) is not list or len(conditions) > 64:
            raise PrivacyChecksError("bounded conjunctive conditions required")
        for condition in conditions:
            if type(condition) is not list or len(condition) != 2:
                raise PrivacyChecksError("condition requires a pair of strings")
            _text(condition[0]); _text(condition[1])
    rules = policy["extra_join_rules"]
    if type(rules) is not list or len(rules) > 64:
        raise PrivacyChecksError("bounded additional join rules required")
    for rule in rules:
        if type(rule) is not list or len(rule) != 3:
            raise PrivacyChecksError("join rule requires kind, kind and reason")
        _kind(rule[0]); _kind(rule[1]); _text(rule[2])
    return policy


def privacy_checks_policy(*, trust_roots: list[str], observer: dict[str, Any],
                          disclosed_fields: list[str], withheld_fields: list[str],
                          bounds: list[dict[str, Any]], co_emitted_ids: list[str],
                          extra_join_rules: list[list[str]],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "observer": observer,
        "disclosed_fields": disclosed_fields, "withheld_fields": withheld_fields,
        "bounds": bounds, "co_emitted_ids": co_emitted_ids, "extra_join_rules": extra_join_rules})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise PrivacyChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "timestamp", "limits"}, "request")
    kind = _kind(request["object_kind"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION), ("coordinate", coordinate(kind))):
        if type(request[field]) is not str or request[field] != expected:
            raise PrivacyChecksError("selected full-record disclosure objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != PrivacyDescriptor(kind).PROPOSITION_DIGEST:
        raise PrivacyChecksError("selected proposition differs")
    subject = request["subject_id"]
    if type(subject) is not str or not subject.strip() or len(subject) > 256:
        raise PrivacyChecksError("bounded subject identifier required")
    _text(request["timestamp"])
    request["limits"] = _limits(request["limits"])
    return request


def privacy_checks_request(*, object_kind: str, subject_id: str, object_digest: str,
                         collection_digest: str, evidence_ref: str, timestamp: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise PrivacyChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(object_kind), "proposition_digest": PrivacyDescriptor(object_kind).PROPOSITION_DIGEST,
        "object_kind": object_kind, "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "timestamp": timestamp, "limits": {**_CEILINGS, **(limits or {})}})


def _charge(value: Any, budget: Budget, depth: int = 0) -> None:
    """Charge structural visits before native evaluation; no machine-time claim."""
    budget.tick()
    if depth > 64:
        raise Unavailable("retained disclosure depth bound exhausted")
    if type(value) is dict:
        for key, child in value.items():
            _charge(key, budget, depth + 1); _charge(child, budget, depth + 1)
    elif type(value) is list:
        for child in value:
            _charge(child, budget, depth + 1)


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = strict_json_loads(data.decode("utf-8"))
        budget = Budget(limits["max_operations"])
        _charge(value, budget); _charge(policy, budget)
        value = _record(value, {"schema_version", "objects"}, "collection")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained disclosure collection version or canonical bytes differ")
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
        composition = assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        by_id = {item.object_id: item for item in objects}
        if subject.object_id in policy["co_emitted_ids"] or any(name not in by_id for name in policy["co_emitted_ids"]):
            raise Refuted("co-disclosure names no distinct selected record")
        co_objects = [by_id[name] for name in policy["co_emitted_ids"]]
        rules = privacy_composition.HIGH_RISK_JOIN_PAIRS + tuple(tuple(row) for row in policy["extra_join_rules"])
        declared = policy["observer"]
        observer = privacy_models.ObserverParty(declared["actor_id"], declared["role"], declared["purpose"], tuple(declared["credentials"]))
        # Namespace kind is authoritative for this screen; payload labels cannot
        # hide the kind or override the independently selected co-disclosures.
        budget.tick(len(co_objects) * len(rules))
        screen = privacy_composition.CompositionDeltaEvaluator(rules)
        admitted, _, _ = screen.evaluate_composition_delta({"object_name": subject.kind.value},
            tuple({"object_name": item.kind.value} for item in co_objects), observer)
        if admitted is not True:
            raise Refuted("selected typed co-disclosure triggers a refusal rule")
        record = subject.to_dict()
        # Reserve a conservative comparison allowance before calling the native
        # checker. Structural visits and these allowances are dimensionless.
        for bound in policy["bounds"]:
            budget.tick(len(record) * (1 + len(bound["admitted_observers"]) + len(bound["admitted_roles"])
                + sum(1 + (len(observer.credentials) if key == "credential" else 1) for key, _ in bound["conditions"])))
        bounds = tuple(privacy_models.DisclosureBound(row["bound_id"], row["field_name"],
            tuple(row["admitted_observers"]), tuple(row["admitted_roles"]),
            tuple(tuple(pair) for pair in row["conditions"])) for row in policy["bounds"])
        surface = privacy_models.DisclosureSurface(subject.kind.value, tuple(policy["disclosed_fields"]), tuple(policy["withheld_fields"]))
        context = privacy_models.EmissionContext(observer, request["timestamp"], tuple(item.to_dict() for item in co_objects))
        result = privacy_engine.EmissionEvaluator(screen).evaluate_emission(record, surface, bounds, context)
        if result.redacted_fields or canonical_bytes(result.emitted_certificate) != canonical_bytes(record):
            raise Refuted("native disclosure does not preserve the complete selected record")
        return MechanismDecision(MechanismOutcome.PASS, "full selected record satisfies declared disclosure bounds",
            {"record_digest": subject.digest, "fields_checked": len(record), "work_units": budget.used,
             "native_receipt_digest": result.receipt["receipt_digest"], "typed_rule_screen": "PASS",
             "observer_authentication": "NOT_ESTABLISHED", "general_composition_safety": "NOT_ESTABLISHED",
             "underlying_certificate_validity": "NOT_ESTABLISHED", "emission": "NOT_PERFORMED"})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return MechanismDecision(MechanismOutcome.FAIL, "selected disclosure record, policy or native admission differs")


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "collection_digest", "policy_digest", "timestamp")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _PrivacyChecksMechanism:
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
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained disclosure collection is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise PrivacyChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_PrivacyChecksMechanism(request, policy))
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
        raise PrivacyChecksError("certificate byte bound exhausted")
    return encoded


def build_privacy_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise PrivacyChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise PrivacyChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_privacy_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise PrivacyChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise PrivacyChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise PrivacyChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise PrivacyChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise PrivacyChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, PrivacyChecksError):
            raise
        raise PrivacyChecksError("invalid full-record disclosure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "SCOPE", "PrivacyChecksError",
           "coordinate", "registration", "privacy_checks_policy", "privacy_checks_request",
           "build_privacy_checks_certificate", "recheck_privacy_checks_certificate"]
