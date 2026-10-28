"""Current benchmark specification graph (BENCH) native check certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Time is milliseconds; memory is bytes; scores are dimensionless.
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
from verifier.domains import bench as bench_module
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-bench-checks-request-1"
POLICY_VERSION = "verifier-current-bench-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-bench-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-bench-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-bench-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"problems": "BENCH-1.2", "oracles": "BENCH-1.4",
          "budgets": "BENCH-3.6", "coverage": "BENCH-4.4"}
_CLAIMS = {
    "problems": "The selected nonempty problem inventory has exactly one retained candidate answer per problem, each bound to the exact problem specification and positive weight.",
    "oracles": "The selected built-in oracle is actually executed for every bound retained answer, and the exact weighted solved fraction satisfies the independently selected minimum score.",
    "budgets": "Every bound retained timing and memory observation lies within its selected positive problem ceiling, without numeric coercion hiding an excess.",
    "coverage": "The complete selected problem/run inventory is checked by its native oracles; exact weighted scoring satisfies the selected minimum and agrees with the retained reported score within the fixed reporting tolerance.",
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise BenchChecksError("unsupported benchmark check")
    return value


def scope(check: str) -> str:
    return "finite_retained_bench_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "BENCH", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact BENCH record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["oracle correctness beyond the selected built-in predicate", "live execution or measurement authenticity",
                       "population validity, contamination, sampling or generalization", "attempt history or hardware enforcement",
                       "whole tier or object-profile conformance"]}


def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class BenchDescriptor:
    """One exact publicly selectable benchmark proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class BenchChecksError(ValueError):
    """Malformed external selection or substituted benchmark certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise BenchChecksError(label + " fields differ")
    if set(value) != fields:
        raise BenchChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise BenchChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, bench_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_BENCH_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise BenchChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise BenchChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise BenchChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise BenchChecksError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def bench_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise BenchChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "BENCH")):
        if type(request[field]) is not str or request[field] != expected:
            raise BenchChecksError("selected benchmark objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise BenchChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise BenchChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def bench_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise BenchChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "BENCH", "subject_id": subject_id, "object_digest": object_digest,
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
        if len(matches) != 1 or matches[0].kind.value != "BENCH" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        operands = dict(matches[0].operands)
        if any(len(operands[role]) != 1 for role in ("verifier", "data")):
            raise Unavailable("one selected verifier and problem dataset are required")
        records = {item.object_id: item for item in objects}
        verifier = records[operands["verifier"][0]]
        dataset = records[operands["data"][0]]
        common_module.same(verifier.payload, {"mechanism_id": MECHANISM_ID,
            "mechanism_digest": mechanism_digest()}, "selected benchmark verifier differs from installed mechanism")
        common_module.same(dataset.payload, {"problems": common_module.need(matches[0].payload, "problems")},
                           "selected dataset differs from benchmark problem inventory")
        if value["inputs"] is None:
            raise Unavailable("retained benchmark inputs absent")
        retained = common_module.obj(value["inputs"])
        if any(type(key) is not str for key in retained) or set(retained) - {"runs", "score"}:
            raise Refuted("unsupported retained benchmark input")
        result = bench_module.evaluate(request["check"], matches[0].payload, retained, budget)
        return MechanismDecision(MechanismOutcome.PASS, "selected retained benchmark check reproduced",
                                 {"benchmark": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _BenchChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound benchmark proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained benchmark evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise BenchChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_BenchChecksMechanism(request, policy))
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
        raise BenchChecksError("certificate byte bound exhausted")
    return encoded


def build_bench_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise BenchChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise BenchChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_bench_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise BenchChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise BenchChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise BenchChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise BenchChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise BenchChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, BenchChecksError):
            raise
        raise BenchChecksError("invalid retained benchmark certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "BenchDescriptor", "BenchChecksError", "bench_checks_policy",
           "bench_checks_request", "build_bench_checks_certificate", "recheck_bench_checks_certificate"]
