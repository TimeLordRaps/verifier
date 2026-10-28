"""Bind selected ENV configuration names to finite declared value domains.

Verifier Standard (VSTD); verifiable execution environment (ENV); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless; size limits measure bytes. Retained values are not live host
observations or evidence that the external selection named every real setting.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import math
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
from verifier.domains.contracts import retained_selection, typed_facets


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ENV-1.4"
REQUEST_VERSION = "verifier-current-env-configuration-surface-request-1"
POLICY_VERSION = "verifier-current-env-configuration-surface-policy-1"
CERTIFICATE_VERSION = "verifier-current-env-configuration-surface-certificate-1"
EVIDENCE_VERSION = "verifier-current-env-configuration-surface-evidence-1"
MECHANISM_ID = "verifier.current-env.selected-configuration-surface.1"
SCOPE = "finite_selected_required_configuration_names_and_value_domains"
_CEILINGS = {
    "max_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 6 * 1024 * 1024,
    "max_child_certificate_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 512 * 1024
_MAX_SURFACE_BYTES = 64 * 1024
_MAX_SCHEMA_NODES = 512
_MAX_SCHEMA_DEPTH = 16
_MAX_SAFE_INTEGER = 2**53 - 1


class EnvConfigurationSurfaceError(ValueError):
    """Malformed external selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ENV",
        "scope": SCOPE,
        "proposition": (
            "The exact selected finite required configuration names and value "
            "domains equal the ENV declaration, every declared name has one "
            "retained value in its domain, and the same selected ENV and finite "
            "collection pass a replayed ENV-1.1 structural certificate."
        ),
        "prerequisites": [
            "externally selected required surface, ENV-1.1 request, policy and "
            "retained canonical certificate over the identical ENV and collection",
        ],
        "exclusions": [
            "whether the external selection names every setting of a real host",
            "collector authenticity or observation of a running process",
            "secret value disclosure, physical isolation, authority or polished issuance",
            "whole facets-tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EnvConfigurationSurfaceDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection, typed_facets,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_TYPED_FACETS.md",
        "CURRENT_ENV_CONFIGURATION_SURFACE.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=EnvConfigurationSurfaceError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def env_configuration_surface_policy(*, trust_roots: list[str],
                                     max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                                     ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _name(value: Any) -> str:
    if (type(value) is not str or not value.strip() or len(value) > 128
            or not value.isprintable()):
        raise EnvConfigurationSurfaceError("bounded configuration name required")
    return value


def _plain_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
        raise EnvConfigurationSurfaceError("selected value-domain structure bound exhausted")
    if value is None or type(value) in (bool, str):
        return
    if type(value) is int and abs(value) <= _MAX_SAFE_INTEGER:
        return
    if type(value) is float and math.isfinite(value) and abs(value) <= 1e100:
        return
    if type(value) is list and len(value) <= 64:
        for item in value:
            _plain_json(item, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict and len(value) <= 64 and all(type(key) is str for key in value):
        for key, item in value.items():
            _name(key)
            _plain_json(item, depth=depth + 1, nodes=nodes)
        return
    raise EnvConfigurationSurfaceError("bounded plain JSON domain value required")


def _bounds(domain: dict[str, Any], *, number: bool = False) -> None:
    lower, upper = domain["minimum"], domain["maximum"]
    if number:
        admitted = lambda value: (type(value) in (int, float)
                                  and abs(value) <= 1e100
                                  and (type(value) is int and abs(value) <= _MAX_SAFE_INTEGER
                                       or type(value) is float and math.isfinite(value)))
    else:
        admitted = lambda value: type(value) is int and abs(value) <= _MAX_SAFE_INTEGER
    if not admitted(lower) or not admitted(upper) or lower > upper:
        raise EnvConfigurationSurfaceError("finite ordered selected domain bounds required")


def _domain(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
        raise EnvConfigurationSurfaceError("selected domain structure bound exhausted")
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise EnvConfigurationSurfaceError("selected domain must be a plain tagged record")
    kind = value["kind"]
    shapes = {
        "literal": {"kind", "value"},
        "enum": {"kind", "values"},
        "boolean": {"kind"},
        "integer": {"kind", "minimum", "maximum"},
        "number": {"kind", "minimum", "maximum"},
        "string": {"kind", "minimum_length", "maximum_length"},
        "array": {"kind", "items", "minimum_length", "maximum_length"},
        "record": {"kind", "fields"},
        "union": {"kind", "options"},
    }
    if kind not in shapes or set(value) != shapes[kind] or any(type(k) is not str for k in value):
        raise EnvConfigurationSurfaceError("selected domain shape differs")
    if kind == "literal":
        _plain_json(value["value"], depth=depth + 1, nodes=nodes)
    elif kind == "enum":
        entries = value["values"]
        if type(entries) is not list or not 1 <= len(entries) <= 64:
            raise EnvConfigurationSurfaceError("nonempty bounded enum required")
        for item in entries:
            _plain_json(item, depth=depth + 1, nodes=nodes)
        if len({canonical_bytes(item) for item in entries}) != len(entries):
            raise EnvConfigurationSurfaceError("enum values must be distinct")
    elif kind in ("integer", "number"):
        _bounds(value, number=(kind == "number"))
    elif kind in ("string", "array"):
        lower, upper = value["minimum_length"], value["maximum_length"]
        if (type(lower) is not int or type(upper) is not int
                or not 0 <= lower <= upper <= 4096):
            raise EnvConfigurationSurfaceError("finite ordered length bounds required")
        if kind == "array":
            _domain(value["items"], depth=depth + 1, nodes=nodes)
    elif kind == "record":
        fields = value["fields"]
        if type(fields) is not dict or len(fields) > 64 or any(type(k) is not str for k in fields):
            raise EnvConfigurationSurfaceError("bounded record domain fields required")
        for key, item in fields.items():
            _name(key)
            _domain(item, depth=depth + 1, nodes=nodes)
    elif kind == "union":
        options = value["options"]
        if type(options) is not list or not 1 <= len(options) <= 16:
            raise EnvConfigurationSurfaceError("nonempty bounded union required")
        for item in options:
            _domain(item, depth=depth + 1, nodes=nodes)
        if len({canonical_bytes(item) for item in options}) != len(options):
            raise EnvConfigurationSurfaceError("union branches must be distinct")


def _surface(value: Any) -> dict[str, Any]:
    if (type(value) is not dict or not 1 <= len(value) <= 64
            or any(type(key) is not str for key in value)):
        raise EnvConfigurationSurfaceError("nonempty bounded required surface needed")
    nodes = [0]
    for key, domain in value.items():
        _name(key)
        _domain(domain, depth=0, nodes=nodes)
    try:
        raw = canonical_bytes(value)
        if len(raw) > _MAX_SURFACE_BYTES:
            raise EnvConfigurationSurfaceError("selected surface byte bound exhausted")
        return strict_json_loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, EnvConfigurationSurfaceError):
            raise
        raise EnvConfigurationSurfaceError("invalid selected surface") from exc


def _same_json(left: Any, right: Any, budget: common_module.Budget) -> bool:
    left_bytes, right_bytes = canonical_bytes(left), canonical_bytes(right)
    budget.tick(len(left_bytes) + len(right_bytes))
    return left_bytes == right_bytes


def _matches(domain: dict[str, Any], value: Any,
             budget: common_module.Budget) -> bool:
    budget.tick()
    kind = domain["kind"]
    if kind == "literal":
        return _same_json(value, domain["value"], budget)
    if kind == "enum":
        return any(_same_json(value, item, budget) for item in domain["values"])
    if kind == "boolean":
        return type(value) is bool
    if kind == "integer":
        return (type(value) is int and abs(value) <= _MAX_SAFE_INTEGER
                and domain["minimum"] <= value <= domain["maximum"])
    if kind == "number":
        return (type(value) in (int, float)
                and (type(value) is int and abs(value) <= _MAX_SAFE_INTEGER
                     or type(value) is float and math.isfinite(value))
                and domain["minimum"] <= value <= domain["maximum"])
    if kind == "string":
        if type(value) is not str:
            return False
        budget.tick(len(value))
        return domain["minimum_length"] <= len(value) <= domain["maximum_length"]
    if kind == "array":
        if type(value) is not list:
            return False
        budget.tick(len(value))
        return (domain["minimum_length"] <= len(value) <= domain["maximum_length"]
                and all(_matches(domain["items"], item, budget) for item in value))
    if kind == "record":
        fields = domain["fields"]
        if type(value) is not dict:
            return False
        budget.tick(len(value))
        return (set(value) == set(fields)
                and all(_matches(fields[key], value[key], budget) for key in fields))
    return any(_matches(option, value, budget) for option in domain["options"])


def _child_selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(request) is not dict or type(policy) is not dict:
        raise EnvConfigurationSurfaceError("selected ENV-1.1 request and policy must be plain")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(request, budget)
        common_module.inspect_structure(policy, budget)
        if len(canonical_bytes(request)) + len(canonical_bytes(policy)) > _MAX_CHILD_SELECTION_BYTES:
            raise EnvConfigurationSurfaceError("selected ENV-1.1 byte bound exhausted")
        child_request = typed_facets._request(request)
        child_policy = typed_facets._policy(policy)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError,
            Unavailable) as exc:
        if isinstance(exc, EnvConfigurationSurfaceError):
            raise
        raise EnvConfigurationSurfaceError("invalid selected ENV-1.1 prerequisite") from exc
    if (child_request["coordinate"] != "ENV-1.1"
            or child_request["object_kind"] != "ENV"
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise EnvConfigurationSurfaceError("selected ENV-1.1 prerequisite differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "required_surface",
        "facets_certificate_digest", "facets_request", "facets_policy",
    }, "request", EnvConfigurationSurfaceError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "ENV"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise EnvConfigurationSurfaceError("selected ENV configuration objective differs")
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise EnvConfigurationSurfaceError("bounded ENV subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest",
                "facets_certificate_digest"):
        retained_selection.commitment(request[key], EnvConfigurationSurfaceError)
    request["required_surface"] = _surface(request["required_surface"])
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, EnvConfigurationSurfaceError,
    )
    child_request, child_policy = _child_selection(
        request["facets_request"], request["facets_policy"],
    )
    if (child_request["subject_id"] != request["subject_id"]
            or child_request["object_digest"] != request["object_digest"]
            or child_request["collection_digest"] != request["collection_digest"]):
        raise EnvConfigurationSurfaceError("selected ENV-1.1 subject or collection differs")
    request["facets_request"], request["facets_policy"] = child_request, child_policy
    return request


def env_configuration_surface_request(*, subject_id: str, object_digest: str,
                                      collection_digest: str, evidence_ref: str,
                                      required_surface: dict[str, Any],
                                      facets_certificate_digest: str,
                                      facets_request: dict[str, Any],
                                      facets_policy: dict[str, Any],
                                      policy: dict[str, Any],
                                      limits: dict[str, int] | None = None,
                                      ) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise EnvConfigurationSurfaceError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ENV", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
        "required_surface": required_surface,
        "facets_certificate_digest": facets_certificate_digest,
        "facets_request": facets_request, "facets_policy": facets_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "required_surface_digest": "sha256:" + canonical_digest(request["required_surface"]),
        "facets_certificate_digest": request["facets_certificate_digest"],
        "facets_selection_digest": "sha256:" + canonical_digest({
            "request": request["facets_request"], "policy": request["facets_policy"],
        }),
    }


def _child_bytes(encoded: Any, *, maximum: int) -> bytes:
    if type(encoded) is not str:
        raise Refuted("retained ENV-1.1 encoding must be text")
    if not encoded:
        raise Unavailable("selected retained ENV-1.1 certificate absent")
    if len(encoded) > (maximum + 2) // 3 * 4 + 4:
        raise Unavailable("selected retained ENV-1.1 encoded bound exhausted")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained ENV-1.1 encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise Refuted("retained ENV-1.1 encoding noncanonical")
    if len(raw) > maximum:
        raise Unavailable("selected retained ENV-1.1 byte bound exhausted")
    return raw


def _child_evidence(certificate: bytes, expected_ref: str) -> dict[str, Any]:
    envelope = strict_json_loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) != {expected_ref}:
        raise Refuted("selected ENV-1.1 retained collection absent")
    store = EvidenceStore()
    store.import_base64(payloads)
    return strict_json_loads(store.resolve(expected_ref).decode("utf-8"))


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "facets_certificate_b64"},
            "evidence", EnvConfigurationSurfaceError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained ENV configuration evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        child_bytes = _child_bytes(
            value["facets_certificate_b64"],
            maximum=limits["max_child_certificate_bytes"],
        )
        if ("sha256:" + hashlib.sha256(child_bytes).hexdigest()
                != request["facets_certificate_digest"]):
            raise Refuted("retained ENV-1.1 bytes differ from external selection")
        try:
            child = typed_facets.recheck_typed_facets_certificate(
                child_bytes, expected_request=request["facets_request"],
                policy=request["facets_policy"],
            )
        except typed_facets.TypedFacetsError as exc:
            raise Refuted("selected ENV-1.1 certificate did not reproduce") from exc
        outcome = child["status"]
        if outcome not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected ENV-1.1 result is unsupported")
        if outcome != "PASS":
            return MechanismDecision(
                MechanismOutcome(outcome), "selected ENV-1.1 facets did not pass",
            )
        child_evidence = _child_evidence(
            child_bytes, request["facets_request"]["evidence_ref"],
        )
        common_module.inspect_structure(child_evidence, budget)
        rows = child_evidence["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        matches = [row for row in rows if row["object_id"] == request["subject_id"]]
        if len(matches) != 1:
            raise Refuted("retained ENV subject absent or duplicate")
        subject = NamespaceObject.create(**matches[0])
        if subject.kind.value != "ENV" or subject.digest != request["object_digest"]:
            raise Refuted("retained ENV subject differs from external selection")
        artifact = subject.payload
        if artifact.get("scope") != "retained-process-observations":
            raise Unavailable("selected ENV scope has no admitted configuration checker")
        declared = artifact.get("configuration_surface")
        if (type(declared) is not dict
                or canonical_bytes(declared) != canonical_bytes(request["required_surface"])):
            raise Refuted("ENV configuration surface differs from external selection")
        config = artifact.get("configuration")
        if type(config) is not dict or set(config) != set(declared):
            raise Refuted("ENV configuration names differ from complete selected surface")
        for name, domain in request["required_surface"].items():
            if not _matches(domain, config[name], budget):
                raise Refuted("ENV configuration value outside selected domain")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected configuration surface is closed and each retained value is in domain",
            {"names_checked": len(config), "facets_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _EnvConfigurationSurfaceMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound ENV configuration proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained ENV configuration bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EnvConfigurationSurfaceError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_EnvConfigurationSurfaceMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ENV", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "facets_profile_conformance": "NOT_ESTABLISHED",
        "live_host_configuration": "NOT_ESTABLISHED",
        "external_surface_completeness": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise EnvConfigurationSurfaceError("configuration certificate byte bound exhausted")
    return encoded


def build_env_configuration_surface_certificate(request: dict[str, Any],
                                                evidence_bytes: bytes | None, *,
                                                policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise EnvConfigurationSurfaceError("immutable bounded configuration evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EnvConfigurationSurfaceError("configuration evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_env_configuration_surface_certificate(certificate_bytes: bytes, *,
                                                  expected_request: dict[str, Any],
                                                  policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise EnvConfigurationSurfaceError("bounded immutable configuration certificate required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate", EnvConfigurationSurfaceError,
        )
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise EnvConfigurationSurfaceError("canonical configuration certificate version differs")
        if value["request"] != selected:
            raise EnvConfigurationSurfaceError("configuration certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise EnvConfigurationSurfaceError("retained configuration evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EnvConfigurationSurfaceError("configuration certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, EnvConfigurationSurfaceError):
            raise
        raise EnvConfigurationSurfaceError("invalid retained ENV configuration certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SCOPE", "EnvConfigurationSurfaceDescriptor", "EnvConfigurationSurfaceError",
    "registration", "mechanism_digest", "env_configuration_surface_policy",
    "env_configuration_surface_request", "build_env_configuration_surface_certificate",
    "recheck_env_configuration_surface_certificate",
]
