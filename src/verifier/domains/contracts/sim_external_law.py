"""Current SIM-3.4: exact selected statement of an external modelled law.

Simulation (SIM) is a generative simulation specification. Verifier Standard
(VSTD) binds canonical JavaScript Object Notation (JSON) with Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless and limits count bytes.
This checks a represented statement, not a physical law or its authority.
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
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-3.4"
REQUEST_VERSION = "verifier-current-sim-external-law-request-1"
POLICY_VERSION = "verifier-current-sim-external-law-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-external-law-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-external-law-evidence-1"
LAW_VERSION = "verifier-external-law-statement-1"
MECHANISM_ID = "verifier.current-sim.selected-external-law-statement.1"
SCOPE = "selected_distinct_external_law_statement"
PAYLOAD_SCOPE = "selected-external-law-statement"
# Admitted members of a composable retained SIM payload scope, in ascending
# code-point order. Current SIM-2.1 (sim_dynamics) keeps this identical tuple
# so one exact SIM record can be selected by both routes separately; neither
# route's pass establishes the other.
SCOPE_MEMBERS = (PAYLOAD_SCOPE, "selected-retained-trajectory-replay")
_CEILINGS = {"max_objects": 64, "max_operations": 20000,
             "max_composition_operations": 20000,
             "max_items": 4096, "max_evidence_bytes": 1024 * 1024,
             "max_payload_bytes": 1024 * 1024,
             "max_reference_bytes": 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024


class SimExternalLawError(ValueError):
    """Malformed selection, policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "The exact selected SIM record names a distinct typed OBJECT operand "
            "whose retained bounded statement, applicability and source reference "
            "are selected outside the SIM record and assert the physical law "
            "the SIM models."),
        "prerequisites": [
            "exact externally selected SIM and law OBJECT records in a finite "
            "replayed typed collection, selected statement and source reference, "
            "canonical retained evidence and finite limits"],
        "exclusions": [
            "truth, dimensional correctness or applicability of the physical law",
            "independent source existence, source authority or citation resolution",
            "actual simulation correspondence, historical execution or law independence",
            "whole SIM statics tier, object profile, disclosure or publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimExternalLawDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimExternalLawError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SimExternalLawError)


def _text(value: Any, label: str, max_length: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > max_length:
        raise SimExternalLawError("bounded nonempty " + label + " required")
    return value


def _declares_scope(value: Any) -> bool:
    """Whether the retained payload ``scope`` declares this route's member.

    A string is the legacy scalar form and declares exactly one member. A
    list is the composable form: nonempty, string members only, every member
    admitted, no repeated member, ascending code-point order. A malformed
    list is refuted as a present contradiction; it is never reordered,
    deduplicated or otherwise canonicalized by the checker.
    """
    if type(value) is str:
        return value == PAYLOAD_SCOPE
    if type(value) is not list:
        return False
    if not value or any(type(member) is not str for member in value):
        raise Refuted("composable SIM scope requires nonempty string members")
    if any(member not in SCOPE_MEMBERS for member in value):
        raise Refuted("composable SIM scope names an unknown member")
    if len(set(value)) != len(value):
        raise Refuted("composable SIM scope repeats a member")
    if value != sorted(value):
        raise Refuted("composable SIM scope is not in ascending code-point order")
    return PAYLOAD_SCOPE in value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_EXTERNAL_LAW.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SimExternalLawError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def sim_external_law_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "collection_digest", "law_object_id", "law_object_digest",
        "law_statement_digest", "source_ref", "evidence_ref", "policy_digest",
        "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("object_kind", "SIM"),
                            ("proposition_digest", PROPOSITION_DIGEST)):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimExternalLawError("selected SIM external-law objective differs")
    _text(selected["subject_id"], "SIM subject", 256)
    _text(selected["law_object_id"], "external law identifier", 256)
    if selected["subject_id"] == selected["law_object_id"]:
        raise SimExternalLawError("external law must be a distinct object")
    for field in ("object_digest", "collection_digest", "law_object_digest",
                  "law_statement_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    _text(selected["source_ref"], "selected source reference", 512)
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimExternalLawError)
    return selected


def sim_external_law_request(*, subject_id: str, object_digest: str,
        collection_digest: str, law_object_id: str, law_object_digest: str,
        law_statement_digest: str, source_ref: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise SimExternalLawError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "law_object_id": law_object_id, "law_object_digest": law_object_digest,
        "law_statement_digest": law_statement_digest, "source_ref": source_ref,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained external-law evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"},
                               "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        subject = [item for item in objects if item.object_id == request["subject_id"]]
        law = [item for item in objects if item.object_id == request["law_object_id"]]
        if (len(subject) != 1 or subject[0].kind.value != "SIM"
                or subject[0].digest != request["object_digest"]
                or len(law) != 1 or law[0].kind.value != "OBJECT"
                or law[0].digest != request["law_object_digest"]):
            raise Refuted("selected SIM or law record differs")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value),
                                     composition.reason)
        payload = subject[0].payload
        if (payload.get("scope") is None
                or payload.get("modelled_law_object_id") is None):
            raise Unavailable("SIM external-law declaration absent")
        if (not _declares_scope(payload["scope"])
                or payload["modelled_law_object_id"] != law[0].object_id
                or law[0].object_id not in dict(subject[0].operands)["objects"]):
            raise Refuted("SIM external-law relation differs")
        law_payload = law[0].payload
        for field in ("schema_version", "statement", "applicability", "source_ref"):
            if field not in law_payload or law_payload[field] is None:
                raise Unavailable("selected external-law " + field + " absent")
        if set(law_payload) != {"schema_version", "statement", "applicability", "source_ref"}:
            raise Refuted("external-law statement fields differ")
        if law_payload["schema_version"] != LAW_VERSION:
            raise Refuted("external-law statement version differs")
        for field, maximum in (("statement", 8192), ("applicability", 4096),
                               ("source_ref", 512)):
            if (type(law_payload[field]) is not str
                    or not law_payload[field].strip()
                    or len(law_payload[field]) > maximum):
                raise Refuted("bounded external-law " + field + " required")
        if ("sha256:" + canonical_digest(law_payload["statement"])
                != request["law_statement_digest"]
                or law_payload["source_ref"] != request["source_ref"]):
            raise Refuted("external law differs from independent selection")
        return MechanismDecision(MechanismOutcome.PASS,
            "exact SIM-to-distinct-law statement relation reproduced",
            {"objects": composition.objects_checked,
             "statement_bytes": len(canonical_bytes(law_payload["statement"])),
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimExternalLawMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {
                    "request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound external-law proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected external-law bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimExternalLawError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimExternalLawMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_3_conformance": "NOT_ESTABLISHED",
        "physical_law_truth": "NOT_ESTABLISHED",
        "physical_applicability": "NOT_ESTABLISHED",
        "external_source_authority": "NOT_ESTABLISHED",
        "external_origin": "NOT_ESTABLISHED",
        "law_independence": "NOT_ESTABLISHED",
        "publication_authority": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SimExternalLawError("external-law certificate byte bound exhausted")
    return encoded


def build_sim_external_law_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise SimExternalLawError("immutable bounded external-law evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimExternalLawError("external-law evidence differs from selected bytes")
    return _build(selected, admitted, store)


def recheck_sim_external_law_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SimExternalLawError("bounded immutable external-law certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result",
             "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SimExternalLawError("canonical selected external-law certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimExternalLawError("retained external-law evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimExternalLawError("external-law certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SimExternalLawError):
            raise
        raise SimExternalLawError("invalid retained external-law certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SimExternalLawDescriptor",
    "SimExternalLawError", "registration", "sim_external_law_policy",
    "sim_external_law_request", "build_sim_external_law_certificate",
    "recheck_sim_external_law_certificate"]
