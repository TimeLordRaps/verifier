"""Bind exact retained ENV entrypoint and interpreter files and version labels.

Verifiable execution environment (ENV); Verifier Standard (VSTD); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless and size limits count bytes. Version labels are selected claims,
not observed program versions or proof of execution.
"""
from __future__ import annotations

import base64
import binascii
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
from verifier.domains.contracts import env_checks, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ENV-1.3"
REQUEST_VERSION = "verifier-current-env-executable-request-1"
POLICY_VERSION = "verifier-current-env-executable-policy-1"
CERTIFICATE_VERSION = "verifier-current-env-executable-certificate-1"
EVIDENCE_VERSION = "verifier-current-env-executable-evidence-1"
MECHANISM_ID = "verifier.current-env.retained-executable-coordinates.1"
SCOPE = "finite_retained_env_entrypoint_interpreter_binding"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 6 * 1024 * 1024,
    "max_child_certificate_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 512 * 1024


class EnvExecutableError(ValueError):
    """Malformed external selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ENV",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact ENV entrypoint and interpreter "
            "logical paths, byte commitments and version labels equal its "
            "retained runtime coordinates; both files are in the identical "
            "selected inventory rehashed by a replayed ENV-1.2 certificate."
        ),
        "prerequisites": [
            "externally selected ENV-1.2 request, policy and retained canonical "
            "certificate, exact ENV record and finite limits",
        ],
        "exclusions": [
            "observed program version, executable format or actual dispatch",
            "interpreter compatibility, complete environment or toolchain closure",
            "physical host isolation, external origin, authority or polished issuance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EnvExecutableDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, env_checks, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_ENV_CHECKS.md", "CURRENT_ENV_EXECUTABLE.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=EnvExecutableError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def env_executable_policy(*, trust_roots: list[str],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                          ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _logical_path(value: Any) -> str:
    if (type(value) is not str or not value or len(value) > 256
            or not value.isprintable() or "\\" in value or ":" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise EnvExecutableError("bounded relative logical inventory path required")
    return value


def _version(value: Any) -> str:
    if (type(value) is not str or not value.strip() or len(value) > 128
            or not value.isprintable()):
        raise EnvExecutableError("bounded selected version label required")
    return value


def _child_selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(request) is not dict or type(policy) is not dict:
        raise EnvExecutableError("selected ENV-1.2 request and policy must be plain records")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(request, budget)
        common_module.inspect_structure(policy, budget)
        if len(canonical_bytes(request)) + len(canonical_bytes(policy)) > _MAX_CHILD_SELECTION_BYTES:
            raise EnvExecutableError("selected ENV-1.2 byte bound exhausted")
        child_request = env_checks._request(request)
        child_policy = env_checks._policy(policy)
    except (ValueError, TypeError, KeyError, RecursionError,
            OverflowError, Unavailable) as exc:
        if isinstance(exc, EnvExecutableError):
            raise
        raise EnvExecutableError("invalid selected ENV-1.2 prerequisite") from exc
    if (child_request["check"] != "closure"
            or child_request["coordinate"] != "ENV-1.2"
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise EnvExecutableError("selected ENV-1.2 prerequisite differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "entrypoint_path",
        "entrypoint_digest", "entrypoint_version", "interpreter_path",
        "interpreter_digest", "interpreter_version", "inventory_certificate_digest",
        "inventory_request", "inventory_policy",
    }, "request", EnvExecutableError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "ENV"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise EnvExecutableError("selected ENV executable objective differs")
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise EnvExecutableError("bounded ENV subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest",
                "entrypoint_digest", "interpreter_digest", "inventory_certificate_digest"):
        retained_selection.commitment(request[key], EnvExecutableError)
    for key in ("entrypoint_path", "interpreter_path"):
        _logical_path(request[key])
    for key in ("entrypoint_version", "interpreter_version"):
        _version(request[key])
    if (request["entrypoint_path"] == request["interpreter_path"]
            and (request["entrypoint_digest"] != request["interpreter_digest"]
                 or request["entrypoint_version"] != request["interpreter_version"])):
        raise EnvExecutableError("one selected file cannot carry conflicting runtime labels")
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS, EnvExecutableError)
    child_request, child_policy = _child_selection(
        request["inventory_request"], request["inventory_policy"],
    )
    if (child_request["subject_id"] != request["subject_id"]
            or child_request["object_digest"] != request["object_digest"]
            or child_request["collection_digest"] != request["collection_digest"]):
        raise EnvExecutableError("selected ENV-1.2 subject or collection differs")
    request["inventory_request"], request["inventory_policy"] = child_request, child_policy
    return request


def env_executable_request(*, subject_id: str, object_digest: str,
                           collection_digest: str, evidence_ref: str,
                           entrypoint_path: str, entrypoint_digest: str,
                           entrypoint_version: str, interpreter_path: str,
                           interpreter_digest: str, interpreter_version: str,
                           inventory_certificate_digest: str,
                           inventory_request: dict[str, Any],
                           inventory_policy: dict[str, Any], policy: dict[str, Any],
                           limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise EnvExecutableError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ENV", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
        "entrypoint_path": entrypoint_path, "entrypoint_digest": entrypoint_digest,
        "entrypoint_version": entrypoint_version,
        "interpreter_path": interpreter_path, "interpreter_digest": interpreter_digest,
        "interpreter_version": interpreter_version,
        "inventory_certificate_digest": inventory_certificate_digest,
        "inventory_request": inventory_request, "inventory_policy": inventory_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "entrypoint_path": request["entrypoint_path"],
        "entrypoint_digest": request["entrypoint_digest"],
        "entrypoint_version": request["entrypoint_version"],
        "interpreter_path": request["interpreter_path"],
        "interpreter_digest": request["interpreter_digest"],
        "interpreter_version": request["interpreter_version"],
        "inventory_certificate_digest": request["inventory_certificate_digest"],
        "inventory_selection_digest": "sha256:" + canonical_digest({
            "request": request["inventory_request"],
            "policy": request["inventory_policy"],
        }),
    }


def _child_bytes(encoded: Any, *, maximum: int) -> bytes:
    if type(encoded) is not str:
        raise Refuted("retained ENV-1.2 encoding must be text")
    if not encoded:
        raise Unavailable("selected retained ENV-1.2 certificate absent")
    if len(encoded) > (maximum + 2) // 3 * 4 + 4:
        raise Unavailable("selected retained ENV-1.2 encoded bound exhausted")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained ENV-1.2 encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise Refuted("retained ENV-1.2 encoding noncanonical")
    if len(raw) > maximum:
        raise Unavailable("selected retained ENV-1.2 byte bound exhausted")
    return raw


def _child_evidence(certificate: bytes, expected_ref: str) -> dict[str, Any]:
    envelope = strict_json_loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) != {expected_ref}:
        raise Refuted("selected ENV-1.2 retained evidence absent")
    store = EvidenceStore()
    store.import_base64(payloads)
    return strict_json_loads(store.resolve(expected_ref).decode("utf-8"))


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "inventory_certificate_b64"},
            "evidence", EnvExecutableError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained ENV executable evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        child_bytes = _child_bytes(
            value["inventory_certificate_b64"],
            maximum=limits["max_child_certificate_bytes"],
        )
        if ("sha256:" + hashlib.sha256(child_bytes).hexdigest()
                != request["inventory_certificate_digest"]):
            raise Refuted("retained ENV-1.2 bytes differ from external selection")
        try:
            child = env_checks.recheck_env_checks_certificate(
                child_bytes, expected_request=request["inventory_request"],
                policy=request["inventory_policy"],
            )
        except env_checks.EnvChecksError as exc:
            raise Refuted("selected ENV-1.2 certificate did not reproduce") from exc
        outcome = child["status"]
        if outcome not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected ENV-1.2 result is unsupported")
        if outcome != "PASS":
            return MechanismDecision(
                MechanismOutcome(outcome), "selected ENV-1.2 retained inventory did not pass",
            )
        child_evidence = _child_evidence(
            child_bytes, request["inventory_request"]["evidence_ref"],
        )
        common_module.inspect_structure(child_evidence, budget)
        rows = child_evidence["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        matches = [row for row in rows if row["object_id"] == request["subject_id"]]
        if len(matches) != 1:
            raise Refuted("retained ENV subject absent or duplicate")
        subject = NamespaceObject.create(**matches[0])
        if subject.kind.value != "ENV" or subject.digest != request["object_digest"]:
            raise Refuted("retained ENV subject differs from external selection")
        artifact = subject.payload
        runtime = retained_selection.record(
            artifact.get("runtime"), {"entrypoint", "interpreter"},
            "runtime", EnvExecutableError,
        )
        inventory = artifact.get("files")
        if type(inventory) is not dict:
            raise Refuted("selected ENV software inventory absent")
        for role in ("entrypoint", "interpreter"):
            selected = retained_selection.record(
                runtime[role], {"path", "version"}, role, EnvExecutableError,
            )
            path, version = request[role + "_path"], request[role + "_version"]
            if selected["path"] != path or selected["version"] != version:
                raise Refuted("retained executable path or version label differs")
            if path not in inventory or inventory[path] != request[role + "_digest"]:
                raise Refuted("selected executable bytes absent from retained inventory")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected executable coordinates and labels bind rehashed retained files",
            {"entrypoint_path": request["entrypoint_path"],
             "interpreter_path": request["interpreter_path"],
             "inventory_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _EnvExecutableMechanism:
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
                                     "bound ENV executable proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained ENV executable bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EnvExecutableError("request differs from selected executable policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_EnvExecutableMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ENV", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "facets_profile_conformance": "NOT_ESTABLISHED",
        "observed_program_version": "NOT_ESTABLISHED",
        "actual_execution": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
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
        raise EnvExecutableError("executable certificate byte bound exhausted")
    return encoded


def build_env_executable_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                     *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise EnvExecutableError("immutable bounded executable evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EnvExecutableError("executable evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_env_executable_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise EnvExecutableError("bounded immutable executable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate", EnvExecutableError,
        )
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise EnvExecutableError("canonical executable certificate version differs")
        if value["request"] != selected:
            raise EnvExecutableError("executable certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise EnvExecutableError("retained executable evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EnvExecutableError("executable certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, EnvExecutableError):
            raise
        raise EnvExecutableError("invalid retained ENV executable certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SCOPE", "EnvExecutableDescriptor", "EnvExecutableError", "registration",
    "mechanism_digest", "env_executable_policy", "env_executable_request",
    "build_env_executable_certificate", "recheck_env_executable_certificate",
]
