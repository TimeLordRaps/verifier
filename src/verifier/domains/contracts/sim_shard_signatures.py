"""Current simulation (SIM) closure: signatures on selected retained shards.

Verifier Standard (VSTD) binds canonical JavaScript Object Notation (JSON)
with Secure Hash Algorithm 256-bit (SHA-256). Time values share the selected
model's units; byte limits use bytes and item/operation counts are dimensionless.
Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
This check establishes selected key/message validity, not origin or authority.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core import signature_keys
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, sim_shard_coverage, sim_shard_relations


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-4.3"
REQUEST_VERSION = "verifier-current-sim-shard-signatures-request-1"
POLICY_VERSION = "verifier-current-sim-shard-signatures-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-shard-signatures-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-shard-signatures-evidence-1"
MESSAGE_VERSION = "verifier-current-sim-shard-signature-message-1"
MECHANISM_ID = "verifier.current-sim.selected-shard-signatures.1"
SCOPE = "finite_selected_key_bound_shard_row_signatures"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_signatures": 4096}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_PREFIX = b"verifier-current-sim-shard-signature-1\x00"
_HEX32 = re.compile(r"[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{128}\Z")
_BACKEND_VERSION = "50.0.0"


class SimShardSignaturesError(ValueError):
    """Malformed selection or substituted shard-signature certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For an exact externally selected passing SIM-4.2 certificate, every "
            "retained row of each nonempty policy-required shard has an Ed25519 "
            "signature valid under its externally selected admitted public key, "
            "binding the exact child, policy, subject, shard, step, time and state."),
        "prerequisites": [
            "exact separately selected SIM-4.2 request, policy and retained certificate",
            "child replay PASS and its retained aligned shard rows",
            "nonempty external required-shard policy and admitted public-key pins",
            "exact domain-separated signed messages and canonical 64-byte signatures",
            "bounded checker and optional cryptography 50.0.0 Ed25519 backend"],
        "exclusions": [
            "unrequired shards, independent origin, key custody or signer authority",
            "signature freshness, live key revocation, anti-equivocation or actual execution",
            "cryptographic backend correctness, physical or dimensional truth",
            "no unattributed transition or whole simulated-surface coverage",
            "whole SIM closure tier or object-profile conformance",
            "privacy, consent, governance, security and publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimShardSignaturesDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimShardSignaturesError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SimShardSignaturesError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, retained_selection, signature_keys)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_SHARD_RELATIONS.md",
                 "CURRENT_SIM_SHARD_SIGNATURES.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        "sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in sorted(paths.items())},
        "selected_child_mechanism": sim_shard_relations.mechanism_digest()})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes", "required_shards", "public_keys"}, "policy")
    required = selected.pop("required_shards")
    keys = selected.pop("public_keys")
    if (type(required) is not list or not 1 <= len(required) <= _CEILINGS["max_items"]
            or any(type(name) is not str or not name.strip() or len(name) > 128
                   or name == "root" or "." in name for name in required)
            or required != sorted(set(required))):
        raise SimShardSignaturesError("nonempty sorted unique required shard identifiers needed")
    if (type(keys) is not dict or any(type(name) is not str for name in keys)
            or set(keys) != set(required)):
        raise SimShardSignaturesError("public-key inventory differs from required shards")
    owned_keys: dict[str, str | None] = {}
    for name in required:
        key = keys[name]
        if key is not None:
            if type(key) is not str or _HEX32.fullmatch(key) is None:
                raise SimShardSignaturesError("canonical 32-byte public key required")
            try:
                signature_keys.admit_ed25519_public_key(bytes.fromhex(key))
            except ValueError as exc:
                raise SimShardSignaturesError("selected shard public key is inadmissible") from exc
        owned_keys[name] = key
    admitted = retained_selection.policy(selected, error_type=SimShardSignaturesError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)
    return {**admitted, "required_shards": list(required), "public_keys": owned_keys}


def sim_shard_signatures_policy(*, required_shards: list[str],
        public_keys: dict[str, str | None], trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "required_shards": required_shards,
        "public_keys": public_keys,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "relations_request_digest",
        "relations_policy_digest", "relations_certificate_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "SIM")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimShardSignaturesError("selected SIM shard-signature objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimShardSignaturesError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "relations_request_digest",
                  "relations_policy_digest", "relations_certificate_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimShardSignaturesError)
    return selected


def sim_shard_signatures_request(*, subject_id: str, object_digest: str,
        collection_digest: str, relations_request_digest: str,
        relations_policy_digest: str, relations_certificate_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise SimShardSignaturesError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "relations_request_digest": relations_request_digest,
        "relations_policy_digest": relations_policy_digest,
        "relations_certificate_digest": relations_certificate_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str, *, maximum: int) -> bytes:
    if type(value) is not str or len(value) > (4 * maximum // 3 + 4):
        raise Refuted(label + " must be bounded canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if (len(decoded) > maximum
            or base64.b64encode(decoded).decode("ascii") != value):
        raise Refuted(label + " is noncanonical or exceeds bounds")
    return decoded


def _message(request: dict[str, Any], policy: dict[str, Any], *,
        shard_id: str, step_index: int, time: int | float,
        state: dict[str, int | float]) -> bytes:
    if type(shard_id) is not str or shard_id not in policy["required_shards"]:
        raise SimShardSignaturesError("message shard differs from selected policy")
    if type(step_index) is not int or not 0 <= step_index < _CEILINGS["max_items"]:
        raise SimShardSignaturesError("bounded plain step index required")
    if (type(state) is not dict or not 1 <= len(state) <= _CEILINGS["max_items"]
            or any(type(name) is not str or not name.strip() for name in state)):
        raise SimShardSignaturesError("nonempty finite named message state required")
    common_module.number(time)
    for value in state.values():
        common_module.number(value)
    return _PREFIX + canonical_bytes({
        "schema_version": MESSAGE_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        **{field: request[field] for field in (
            "subject_id", "object_digest", "collection_digest",
            "relations_request_digest", "relations_policy_digest",
            "relations_certificate_digest", "policy_digest")},
        "shard_id": shard_id, "step_index": step_index, "time": time, "state": state})


def sim_shard_signature_message(request: dict[str, Any], *, policy: dict[str, Any],
        shard_id: str, step_index: int, time: int | float,
        state: dict[str, int | float]) -> bytes:
    """Encode selected message bytes; membership still requires child replay.

    The evidence reference is deliberately excluded to avoid a signature/hash
    cycle. Exact child and policy commitments bind every retained row instead.
    This helper neither signs nor establishes origin, authority or membership.
    """
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != "sha256:" + canonical_digest(admitted):
        raise SimShardSignaturesError("message request differs from selected policy")
    return _message(selected, admitted, shard_id=shard_id, step_index=step_index,
                    time=time, state=state)


def _verify_signature(signature: bytes, message: bytes, public_key: bytes) -> None:
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise Unavailable("selected Ed25519 backend unavailable") from exc
    if getattr(cryptography, "__version__", None) != _BACKEND_VERSION:
        raise Unavailable("selected Ed25519 backend version differs")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except UnsupportedAlgorithm as exc:
        raise Unavailable("selected Ed25519 operation unavailable") from exc
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refuted("selected shard row signature is invalid") from exc


def _evaluate(data: bytes, request: dict[str, Any],
              policy: dict[str, Any]) -> MechanismDecision:
    try:
        retained = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "relations_request", "relations_policy",
             "relations_certificate", "signatures"}, "evidence")
        if retained["schema_version"] != EVIDENCE_VERSION or canonical_bytes(retained) != data:
            raise Refuted("retained SIM shard-signature evidence differs")
        budget = common_module.Budget(request["limits"]["max_operations"],
                                      request["limits"]["max_items"])
        common_module.inspect_structure(retained, budget)
        child_request = retained["relations_request"]
        child_policy = retained["relations_policy"]
        signatures = retained["signatures"]
        required = policy["required_shards"]
        if type(signatures) is not dict or set(signatures) != set(required):
            raise Refuted("signature inventory differs from selected required shards")
        count = 0
        for name in required:
            selected_signatures = signatures[name]
            if type(selected_signatures) is not list or not selected_signatures:
                raise Refuted("nonempty signature list required for each selected shard")
            count += len(selected_signatures)
            for signature in selected_signatures:
                if (signature is not None and
                        (type(signature) is not str or _HEX64.fullmatch(signature) is None)):
                    raise Refuted("canonical 64-byte shard signature required")
        if count > request["limits"]["max_signatures"]:
            raise Unavailable("selected signature count bound exhausted")
        for field, value in (("relations_request_digest", child_request),
                             ("relations_policy_digest", child_policy)):
            if "sha256:" + canonical_digest(value) != request[field]:
                raise Refuted("selected " + field + " differs")
        if (type(child_request) is not dict
                or child_request.get("semantic_version") != sim_shard_relations.SEMANTIC_VERSION
                or child_request.get("coordinate") != sim_shard_relations.COORDINATE
                or child_request.get("object_kind") != "SIM"
                or child_request.get("subject_id") != request["subject_id"]
                or child_request.get("object_digest") != request["object_digest"]
                or child_request.get("collection_digest") != request["collection_digest"]):
            raise Refuted("selected SIM-4.2 child subject differs")
        if retained["relations_certificate"] is None:
            raise Unavailable("selected SIM-4.2 certificate absent")
        child_raw = _decode_b64(retained["relations_certificate"],
            "SIM-4.2 certificate", maximum=sim_shard_relations._MAX_CERTIFICATE_BYTES)
        budget.tick(len(child_raw))
        if "sha256:" + hashlib.sha256(child_raw).hexdigest() != request["relations_certificate_digest"]:
            raise Refuted("selected SIM-4.2 certificate bytes differ")
        try:
            child_result = sim_shard_relations.recheck_sim_shard_relations_certificate(
                child_raw, expected_request=child_request, policy=child_policy)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-4.2 certificate does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected SIM-4.2 relations remain UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected SIM-4.2 relations did not pass")
        child = strict_json_loads(child_raw.decode("utf-8"))
        encoded = child["evidence_payloads"][child_request["evidence_ref"]]
        child_data = _decode_b64(encoded, "SIM-4.2 retained evidence",
                                 maximum=sim_shard_relations._CEILINGS["max_evidence_bytes"])
        child_retained = strict_json_loads(child_data.decode("utf-8"))
        shard_raw = _decode_b64(child_retained["shard_certificate"],
            "replayed SIM-4.1 certificate", maximum=sim_shard_coverage._MAX_CERTIFICATE_BYTES)
        shard_child = strict_json_loads(shard_raw.decode("utf-8"))
        shard_data = _decode_b64(
            shard_child["evidence_payloads"][child_retained["shard_request"]["evidence_ref"]],
            "replayed SIM-4.1 retained rows",
                                 maximum=sim_shard_coverage._CEILINGS["max_evidence_bytes"])
        rows_retained = strict_json_loads(shard_data.decode("utf-8"))
        ids, rows = rows_retained["shard_ids"], rows_retained["shard_rows"]
        if not set(required) <= set(ids):
            raise Refuted("required signature shard is outside replayed child")
        for name in required:
            if len(signatures[name]) != len(rows[name]):
                raise Refuted("signature count differs from exact retained shard rows")
        verified = 0
        absent = False
        for name in required:
            key = policy["public_keys"][name]
            for index, row in enumerate(rows[name]):
                signature = signatures[name][index]
                if key is None or signature is None:
                    absent = True
                    continue
                message = _message(request, policy, shard_id=name, step_index=index,
                                   time=row["time"], state=row["state"])
                budget.tick(len(message) + 1)
                _verify_signature(bytes.fromhex(signature), message, bytes.fromhex(key))
                verified += 1
        if absent:
            raise Unavailable("selected shard public key or row signature absent")
        return MechanismDecision(MechanismOutcome.PASS,
            "each selected retained shard row verifies under its selected public key",
            {"required_shards": len(required), "retained_shards": len(ids),
             "verified_signatures": verified,
             "retained_rows": sum(len(rows[name]) for name in required),
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            ArithmeticError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimShardSignaturesMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound SIM shard proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected shard bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimShardSignaturesError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimShardSignaturesMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "selected_shard_signatures": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "all_shard_signatures": "NOT_ESTABLISHED",
        "shard_origin": "NOT_ESTABLISHED", "live_key_revocation": "NOT_ESTABLISHED",
        "whole_surface_coverage": "NOT_ESTABLISHED",
        "sim_tier_4_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
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
        raise SimShardSignaturesError("SIM shard certificate byte bound exhausted")
    return encoded


def build_sim_shard_signatures_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise SimShardSignaturesError("immutable bounded SIM shard evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimShardSignaturesError("SIM shard evidence differs from byte selection")
    return _build(selected, admitted, store)


def recheck_sim_shard_signatures_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SimShardSignaturesError("bounded immutable SIM shard certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SimShardSignaturesError("selected canonical SIM shard certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimShardSignaturesError("retained SIM shard evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimShardSignaturesError("SIM shard certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SimShardSignaturesError):
            raise
        raise SimShardSignaturesError("invalid retained SIM shard certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "MESSAGE_VERSION", "PROPOSITION_DIGEST", "SimShardSignaturesDescriptor",
    "SimShardSignaturesError", "registration", "sim_shard_signatures_policy",
    "sim_shard_signatures_request", "sim_shard_signature_message",
    "build_sim_shard_signatures_certificate",
    "recheck_sim_shard_signatures_certificate"]
