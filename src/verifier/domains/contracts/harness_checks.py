"""Current agent harness (HARNESS) native check certificates.

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
from verifier.domains import harness as harness_module
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-harness-checks-request-1"
POLICY_VERSION = "verifier-current-harness-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-harness-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-harness-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-harness-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"surface": "HARNESS-1.6", "messages": "HARNESS-2.1", "tools": "HARNESS-2.2",
          "effects": "HARNESS-2.3", "transcript": "HARNESS-4.1"}
_CLAIMS = {
    "surface": "The declared observation channels partition into instrumented channels and named gaps, with at least one instrumented channel.",
    "messages": "Every retained record has its exact integer position, admitted role, instrumented channel and matching payload commitment.",
    "tools": "Every retained tool record has exactly one invocation bound to its retained registered declaration and exact input/output payload; the complete invocation inventory matches the selected commitment.",
    "effects": "The complete retained effect inventory matches its selected commitment; every effect names an instrumented effect channel and an existing integer transcript position, with no duplicate entries.",
    "transcript": "The complete retained ordered transcript reproduces both its selected canonical digest and pairwise tree commitment.",
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise HarnessChecksError("unsupported harness check")
    return value


def scope(check: str) -> str:
    return "finite_retained_harness_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "HARNESS", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact HARNESS record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["physical observation, actual tool execution or external side-effect occurrence",
                       "tool functional correctness, undeclared channels or omitted real-world events",
                       "timestamp resolution, observer independence or authentic instrument placement",
                       "unselected objectives, legacy prerequisites, authority or whole tier conformance"]}



def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class HarnessDescriptor:
    """One exact publicly selectable harness proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class HarnessChecksError(ValueError):
    """Malformed external selection or substituted harness certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise HarnessChecksError(label + " fields differ")
    if set(value) != fields:
        raise HarnessChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise HarnessChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, harness_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HARNESS_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise HarnessChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise HarnessChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise HarnessChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise HarnessChecksError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def harness_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise HarnessChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "HARNESS")):
        if type(request[field]) is not str or request[field] != expected:
            raise HarnessChecksError("selected harness objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise HarnessChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise HarnessChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def harness_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise HarnessChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "HARNESS", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
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
        if len(matches) != 1 or matches[0].kind.value != "HARNESS" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        if value["inputs"] is None:
            raise Unavailable("retained native harness inputs are absent")
        retained = common_module.obj(value["inputs"])
        if set(retained) - {"records", "invocations", "effects", "declarations"}:
            raise Refuted("unsupported retained harness input")
        result = harness_module.evaluate(request["check"], subject.payload, retained, budget)
        if request["check"] == "tools":
            declarations = common_module.obj(common_module.need(retained, "declarations"))
            tools = common_module.obj(common_module.need(subject.payload, "tools"))
            common_module.same(sorted(declarations), sorted(tools), "retained tool declaration inventory differs")
            budget.tick(len(declarations))
            for name, declaration in declarations.items():
                common_module.text(name)
                declaration = common_module.obj(declaration)
                common_module.same(common_module.need(declaration, "name"), name, "retained tool declaration name differs")
                common_module.same(common_module.digest(declaration), tools[name], "retained tool declaration differs")
            invocations = common_module.seq(common_module.need(retained, "invocations"), budget, nonempty=False)
            records = common_module.seq(common_module.need(retained, "records"), budget)
            indices = [invocation["index"] for invocation in invocations]
            expected = [index for index, record in enumerate(records) if record["role"] == "tool"]
            if len(indices) != len(set(indices)) or sorted(indices) != expected:
                raise Refuted("retained tool records require exactly one invocation each")
            common_module.same(common_module.digest(invocations), common_module.need(subject.payload, "invocations_digest"),
                               "selected invocation inventory differs")
        elif request["check"] == "effects":
            common_module.same(common_module.digest(common_module.need(retained, "effects")),
                common_module.need(subject.payload, "effects_digest"), "selected effect inventory differs")
        return MechanismDecision(MechanismOutcome.PASS, "selected retained harness check reproduced",
                                 {"harness": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _HarnessChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound harness proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained harness evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HarnessChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_HarnessChecksMechanism(request, policy))
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
        raise HarnessChecksError("certificate byte bound exhausted")
    return encoded


def build_harness_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HarnessChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HarnessChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_harness_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HarnessChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise HarnessChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise HarnessChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise HarnessChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HarnessChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HarnessChecksError):
            raise
        raise HarnessChecksError("invalid retained harness certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "HarnessDescriptor", "HarnessChecksError", "harness_checks_policy",
           "harness_checks_request", "build_harness_checks_certificate", "recheck_harness_checks_certificate"]
