"""Current IDENTITY-4.1 configured presentation prerequisites.

Actual native identity children, scoped Ed25519 source attestations, complete
retained public witnesses and a finite unilateral terminal-controller probe.
Configured source/key attestations do not establish actual personhood, institution
authority, issuer measurement, clock truth, physical enforcement or full closure.
Verifier Standard (VSTD); simulation (SIM); JavaScript Object Notation (JSON);
identifier (ID);
Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

from asyncio import CancelledError
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module, evidence as evidence_module
from verifier.core import receipt as receipt_module, signature_keys
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.receipt import strict_json_loads
from verifier.domains.common import Refuted, Unavailable
from verifier.domains import common as common_module
from verifier.domains.contracts import identity_scope, identity_lifecycle, identity_lifecycle_replay

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "IDENTITY-4.1"
SCOPE = "finite_configured_identity_presentation_prerequisites"
MECHANISM_ID = "verifier.current-object.identity-configured-presentation.1"
REQUEST_VERSION = "verifier-current-identity-presentation-request-1"
POLICY_VERSION = "verifier-current-identity-presentation-policy-1"
EVIDENCE_VERSION = "verifier-current-identity-presentation-evidence-1"
CERTIFICATE_VERSION = "verifier-current-identity-presentation-certificate-1"
SUPPORT_VERSION = "verifier-current-identity-scoped-support-1"
ENVELOPE_VERSION = "verifier-current-identity-source-envelope-1"
PROBE_VERSION = "verifier-current-identity-terminal-probe-1"
CONTROL = "configured-holder-signature-only-terminal-transition-1"
ASSURANCE = "native_identity_scope_replay_plus_configured_signature-1"
PUBLIC_MODE = "complete_retained_public_key_replay-1"
PURPOSES = {"enrollment_authority", "assurance", "attribute", "status", "exit_grant", "simulation_scope"}
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_CEILINGS = {"max_supports": 64, "max_operations": 100000, "max_evidence_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
PROPOSITION = {
    "schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE, "subject_kind": "IDENTITY", "scope": SCOPE,
    "proposition": "The exact independently selected native identity relation and declared lifecycle reproduce PASS. Every selected presentation is eligible under that retained history, and every required scoped enrollment/assurance/attribute/status/SIM/control attestation verifies under its independently configured purpose-specific public source policy. A configured holder-signed probe executes the fixed unilateral terminal transition without issuer countersignature or fee. All witnesses and public keys remain retained for exact public-key replay.",
    "prerequisites": ["exact selected native2/native3 requests/policies/certificate bytes and full identity/collection",
        "externally selected source keys, scope/purpose/time rules, assurance and relied attribute requirements",
        "selected presentation inventory, evaluation/probe time, holder public key/challenge and finite limits"],
    "exclusions": ["actual personhood, human/key-holder authentication or institution/issuer authority",
        "measured assurance, independent actor/control ownership or truth of issuer-attested attributes",
        "actual clock/world-log completeness, real SIM occurrence or physical/production exit enforcement",
        "global artifact availability, general privacy/consent, witness-hiding proof or one-time consumption",
        "whole identity closure, complete metatier/application inventory, full object polish or model correctness"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(PROPOSITION)
ROUTE_DESCRIPTOR = {"coordinate": COORDINATE, "fixed_kind": "IDENTITY", "scope": SCOPE,
    "module": __name__, "policy_builder": "identity_presentation_policy",
    "request_builder": "identity_presentation_request", "builder": "build_identity_presentation_certificate",
    "rechecker": "recheck_identity_presentation_certificate"}


class IdentityPresentationError(ValueError):
    """Malformed external selection or nonreproducing native transport."""


class IdentityPresentationUnavailable(OSError):
    """Retained checking capacity unavailable; no carried result accepted."""


def _digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def _capture(value: Any) -> Any:
    """Own plain JSON before source readers/child calls; no foreign callbacks."""
    nodes = 0
    text_bytes = 0
    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > 100000 or depth > 64:
            raise IdentityPresentationError("external selection capture bound exhausted")
        if type(item) is dict:
            if len(item) > 4096:
                raise IdentityPresentationError("external map bound exhausted")
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise IdentityPresentationError("plain text keys required")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        if type(item) is list:
            if len(item) > 4096:
                raise IdentityPresentationError("external array bound exhausted")
            return [visit(child, depth + 1) for child in item]
        if type(item) is str:
            encoded = item.encode("utf-8")
            text_bytes += len(encoded)
            if len(encoded) > 4 * 1024 * 1024 or text_bytes > 8 * 1024 * 1024:
                raise IdentityPresentationError("external text bound exhausted")
            return item
        if type(item) is int and item.bit_length() <= 256:
            return item
        if item is None or type(item) is bool:
            return item
        raise IdentityPresentationError("plain bounded JSON required")
    try:
        return visit(value, 0)
    except (RuntimeError, UnicodeError) as exc:
        raise IdentityPresentationError("external selection changed or invalid text during capture") from exc


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(k) is not str for k in value) or set(value) != fields:
        raise IdentityPresentationError(label + " fields differ")
    return dict(value)


def registration() -> dict[str, Any]:
    return _capture(PROPOSITION)


def _retained_preflight(data: bytes, maximum: int) -> None:
    """Fence retained bytes/structure before recursive decode or hashing."""
    if type(data) is not bytes:
        raise IdentityPresentationError("immutable retained bytes required")
    if len(data) > maximum:
        raise IdentityPresentationUnavailable("retained byte bound exhausted")
    stack: list[int] = []
    quoted = escaped = atom = False
    nodes = token_bytes = 0
    for unit in data:
        if quoted:
            if escaped:
                escaped = False
            elif unit == 92:
                escaped = True
            elif unit == 34:
                quoted = False
            continue
        if unit == 34:
            quoted, atom = True, False
            nodes += 1
        elif unit in (91, 123):
            stack.append(0)
            nodes += 1
            atom = False
            if len(stack) > 64:
                raise IdentityPresentationUnavailable("retained JSON depth bound exhausted")
        elif unit in (93, 125):
            if stack:
                stack.pop()
            atom = False
        elif unit == 44:
            if stack:
                stack[-1] += 1
                if stack[-1] >= 4096:
                    raise IdentityPresentationUnavailable("retained JSON container bound exhausted")
            atom = False
        elif unit in (9, 10, 13, 32, 58):
            atom = False
        else:
            if not atom:
                nodes += 1
                token_bytes = 0
                atom = True
            token_bytes += 1
            if token_bytes > 256:
                raise IdentityPresentationUnavailable("retained JSON atom bound exhausted")
        if nodes > 100000:
            raise IdentityPresentationUnavailable("retained JSON node bound exhausted")


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise IdentityPresentationError("canonical SHA-256 commitment required")
    return value


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _time(value: Any) -> bool:
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def _public_key(value: Any) -> bytes:
    if type(value) is not str or _KEY.fullmatch(value) is None:
        raise IdentityPresentationError("canonical Ed25519 public key required")
    return signature_keys.admit_ed25519_public_key(bytes.fromhex(value))


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, signature_keys, common_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_IDENTITY_PRESENTATION.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_IDENTITY_PRESENTATION.md"
    paths["identity_presentation_evidence.json"] = Path(__file__).parents[2] / "schemas" / "identity_presentation_evidence.json"
    try:
        return _digest({"sources": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())},
            "native_identity3": identity_scope.mechanism_digest(), "native_identity2": identity_lifecycle.mechanism_digest()})
    except (OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("installed source checking unavailable") from exc


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(_capture(value), {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "identity_scope_policy", "identity_lifecycle_policy", "sources", "requirements",
        "holder_id", "holder_public_key", "public_proof_mode", "max_support_age"}, "policy")
    if selected["schema_version"] != POLICY_VERSION or selected["mechanism_id"] != MECHANISM_ID:
        raise IdentityPresentationError("selected native presentation mechanism differs")
    if _hash(selected["mechanism_digest"]) != mechanism_digest():
        raise IdentityPresentationError("policy differs from installed mechanism")
    roots = selected["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16 or any(not _text(x) for x in roots) or roots != sorted(set(roots)):
        raise IdentityPresentationError("bounded sorted unique trust-root labels required")
    size = selected["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise IdentityPresentationError("unsupported certificate byte bound")
    if not _text(selected["holder_id"]) or not _time(selected["max_support_age"]):
        raise IdentityPresentationError("holder/time rule malformed")
    if selected["holder_public_key"] is not None:
        _public_key(selected["holder_public_key"])
    if not _text(selected["public_proof_mode"]):
        raise IdentityPresentationError("public proof mode required")
    child3 = _record(selected["identity_scope_policy"], {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes"}, "selected child3 policy")
    rebuilt3 = identity_scope.identity_scope_policy(trust_roots=child3["trust_roots"], max_certificate_bytes=child3["max_certificate_bytes"])
    if canonical_bytes(rebuilt3) != canonical_bytes(child3):
        raise IdentityPresentationError("selected child3policy differs")
    child2 = _record(selected["identity_lifecycle_policy"], {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "identity_scope_policy", "max_certificate_bytes"}, "selected child2 policy")
    rebuilt2 = identity_lifecycle.identity_lifecycle_policy(trust_roots=child2["trust_roots"], identity_scope_policy=rebuilt3,
        max_certificate_bytes=child2["max_certificate_bytes"])
    if canonical_bytes(rebuilt2) != canonical_bytes(child2):
        raise IdentityPresentationError("selected child2policy/child3policy differs")
    selected["identity_scope_policy"], selected["identity_lifecycle_policy"] = rebuilt3, rebuilt2
    sources = selected["sources"]
    if type(sources) is not list or len(sources) > 16:
        raise IdentityPresentationError("bounded external source inventory required")
    names = []
    for item in sources:
        source = _record(item, {"source_id", "key_id", "public_key", "purposes", "scopes", "clock_id", "valid_from", "valid_until"}, "source")
        if not all(_text(source[k]) for k in ("source_id", "key_id", "clock_id")):
            raise IdentityPresentationError("source identifiers malformed")
        if source["public_key"] is not None:
            _public_key(source["public_key"])
        if not (_time(source["valid_from"]) and _time(source["valid_until"]) and source["valid_from"] < source["valid_until"]):
            raise IdentityPresentationError("source validity malformed")
        for field in ("purposes", "scopes"):
            items = source[field]
            if type(items) is not list or not 1 <= len(items) <= 64 or any(not _text(x) for x in items) or items != sorted(set(items)):
                raise IdentityPresentationError("source purpose/scope inventory malformed")
        names.append(source["source_id"])
    if names != sorted(set(names)):
        raise IdentityPresentationError("source IDs must be unique and sorted")
    requirements = selected["requirements"]
    if type(requirements) is not list or len(requirements) > 64:
        raise IdentityPresentationError("bounded external requirement inventory required")
    names = []
    for item in requirements:
        row = _record(item, {"requirement_id", "purpose", "source_id", "claim_id", "expected_value"}, "requirement")
        if not all(_text(row[k]) for k in ("requirement_id", "purpose", "source_id", "claim_id")):
            raise IdentityPresentationError("requirement identifiers malformed")
        if type(row["expected_value"]) not in (str, int, bool) or (type(row["expected_value"]) is str and len(row["expected_value"]) > 256):
            raise IdentityPresentationError("bounded typed configured attribute value required")
        names.append(row["requirement_id"])
    if names != sorted(set(names)):
        raise IdentityPresentationError("requirement IDs must be unique and sorted")
    return selected


def identity_presentation_policy(*, trust_roots: list[str], identity_scope_policy: dict[str, Any],
    identity_lifecycle_policy: dict[str, Any], sources: list[dict[str, Any]], requirements: list[dict[str, Any]],
    holder_id: str, holder_public_key: str | None, public_proof_mode: str = PUBLIC_MODE,
    max_support_age: int = 1000000, max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    # Capture caller data before the installed-source reader can mutate shared input.
    values = _capture({"trust_roots": trust_roots, "identity_scope_policy": identity_scope_policy,
        "identity_lifecycle_policy": identity_lifecycle_policy, "sources": sources, "requirements": requirements,
        "holder_id": holder_id, "holder_public_key": holder_public_key, "public_proof_mode": public_proof_mode,
        "max_support_age": max_support_age, "max_certificate_bytes": max_certificate_bytes})
    return _admit_policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), **values})


def _admit_policy(value: Any) -> dict[str, Any]:
    try:
        return _policy(value)
    except (OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("selected native policy source checking unavailable") from exc


def _admit_child_request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    try:
        return identity_lifecycle._request(value, policy)
    except (OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("selected native child request checking unavailable") from exc


_REQUEST_FIELDS = {"schema_version", "semantic_version", "coordinate", "proposition_digest", "object_kind",
    "subject_id", "object_digest", "collection_digest", "identity_scope_request", "identity_lifecycle_request",
    "identity_scope_certificate_ref", "identity_lifecycle_certificate_ref", "binding_digest", "presentation_inventory_digest",
    "clock_id", "evaluation_at", "exit_probe_at", "exit_challenge_digest", "exit_probe_ref", "support_refs",
    "policy_digest", "evidence_ref", "limits"}


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    request = _record(_capture(value), _REQUEST_FIELDS, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("object_kind", "IDENTITY")):
        if request[field] != expected:
            raise IdentityPresentationError("selected presentation objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "identity_scope_certificate_ref",
                  "identity_lifecycle_certificate_ref", "binding_digest", "presentation_inventory_digest",
                  "exit_challenge_digest", "exit_probe_ref", "policy_digest", "evidence_ref"):
        _hash(request[field])
    if request["proposition_digest"] != PROPOSITION_DIGEST or request["policy_digest"] != _digest(policy):
        raise IdentityPresentationError("selected proposition/policy differs")
    if not _text(request["subject_id"]) or not _text(request["clock_id"]) or not _time(request["evaluation_at"]) or not _time(request["exit_probe_at"]):
        raise IdentityPresentationError("subject/clock/time selection malformed")
    limits = _record(request["limits"], set(_CEILINGS), "limits")
    if any(type(limits[k]) is not int or not 1 <= limits[k] <= v for k, v in _CEILINGS.items()):
        raise IdentityPresentationError("unsupported selected limits")
    refs = request["support_refs"]
    if type(refs) is not dict or len(refs) > 64 or any(not _text(k) for k in refs):
        raise IdentityPresentationError("bounded exact support references required")
    for ref in refs.values():
        _hash(ref)
    if set(refs) - {row["requirement_id"] for row in policy["requirements"]}:
        raise IdentityPresentationError("foreign selected support reference")
    child2 = _admit_child_request(request["identity_lifecycle_request"], policy["identity_lifecycle_policy"])
    child3 = request["identity_scope_request"]
    if canonical_bytes(child3) != canonical_bytes(child2["identity_scope_request"]):
        raise IdentityPresentationError("selected native child tuple differs")
    for field in ("subject_id", "object_digest", "collection_digest", "binding_digest", "presentation_inventory_digest", "clock_id", "evaluation_at"):
        if child2[field] != request[field]:
            raise IdentityPresentationError("selected parent/child binding differs")
    if child2["identity_scope_certificate_ref"] != request["identity_scope_certificate_ref"]:
        raise IdentityPresentationError("selected child3byte tuple differs")
    request["identity_lifecycle_request"], request["identity_scope_request"] = child2, _capture(child3)
    return request


def identity_presentation_request(*, identity_lifecycle_request: dict[str, Any], identity_lifecycle_certificate_ref: str,
    exit_probe_at: int, exit_challenge_digest: str, exit_probe_ref: str, support_refs: dict[str, str],
    evidence_ref: str, policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    values = _capture({"child": identity_lifecycle_request, "identity_lifecycle_certificate_ref": identity_lifecycle_certificate_ref,
        "exit_probe_at": exit_probe_at, "exit_challenge_digest": exit_challenge_digest, "exit_probe_ref": exit_probe_ref,
        "support_refs": support_refs, "evidence_ref": evidence_ref, "limits": limits})
    admitted = _admit_policy(policy)
    child = _admit_child_request(values.pop("child"), admitted["identity_lifecycle_policy"])
    overrides = values.pop("limits")
    if overrides is not None and (type(overrides) is not dict or set(overrides) - set(_CEILINGS)):
        raise IdentityPresentationError("unsupported limit override")
    base = {key: child[key] for key in ("subject_id", "object_digest", "collection_digest", "binding_digest",
                                     "presentation_inventory_digest", "clock_id", "evaluation_at", "identity_scope_certificate_ref", "identity_scope_request")}
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "IDENTITY", **base, "identity_lifecycle_request": child,
        **values, "policy_digest": _digest(admitted), "limits": {**_CEILINGS, **(overrides or {})}}, admitted)


def claim_selection_digest(request: dict[str, Any]) -> str:
    """Acyclic signature commitment; artifact byte pins remain separately bound."""
    owned = _capture(request)
    return _digest({k: v for k, v in owned.items() if k not in {"evidence_ref", "support_refs", "exit_probe_ref"}})


def support_signing_bytes(source_id: str, key_id: str, payload: dict[str, Any]) -> bytes:
    return b"verifier-current-identity-scoped-support-1\x00" + canonical_bytes(_capture({"source_id": source_id, "key_id": key_id, "payload": payload}))


def probe_signing_bytes(probe: dict[str, Any]) -> bytes:
    owned = _capture(probe)
    return b"verifier-current-identity-terminal-probe-1\x00" + canonical_bytes({k: v for k, v in owned.items() if k != "signature"})


def _verify_signature(public_key: str, signature: str, message: bytes) -> None:
    raw = _public_key(public_key)
    if type(signature) is not str or _SIGNATURE.fullmatch(signature) is None:
        raise Refuted("canonical signature required")
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise IdentityPresentationUnavailable("public Ed25519 backend unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(bytes.fromhex(signature), message)
    except UnsupportedAlgorithm as exc:
        raise IdentityPresentationUnavailable("public Ed25519 algorithm unavailable") from exc
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refuted("configured source signature does not verify") from exc


def _lifecycle_evidence(certificate: dict[str, Any], child_request: dict[str, Any]) -> dict[str, Any]:
    store = EvidenceStore()
    store.import_base64(certificate["evidence_payloads"])
    if child_request["evidence_ref"] not in store:
        raise Unavailable("selected lifecycle payload absent")
    data = store.resolve(child_request["evidence_ref"])
    _retained_preflight(data, child_request["limits"]["max_evidence_bytes"])
    value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "binding", "events", "presentations",
        "identity_scope_certificate"}, "selected lifecycle evidence")
    if value["schema_version"] != identity_lifecycle.EVIDENCE_VERSION or canonical_bytes(value) != data:
        raise Refuted("selected lifecycle retained schema/canonical bytes differ")
    return value


def _support(value: Any, row: dict[str, Any], source: dict[str, Any] | None, request: dict[str, Any],
             policy: dict[str, Any], binding: dict[str, Any] | None, presentations: list[dict[str, Any]] | None,
             lifecycle: dict[str, Any] | None, probe_ref: str, *, verify: bool = True) -> None:
    """Inspect necessary declared predicates before key/backend availability.

    Partial retained companions confer no native facts or authentication credit.
    The evaluator separately requires actual children and actual signatures.
    """
    missing = []
    envelope = _record(value, {"schema_version", "source_id", "key_id", "payload", "signature"}, "support envelope")
    if (envelope["schema_version"] != ENVELOPE_VERSION or envelope["source_id"] != row["source_id"]
            or not _text(envelope["key_id"]) or (source is not None and envelope["key_id"] != source["key_id"])):
        raise Refuted("support source/key/schema differs")
    if type(envelope["signature"]) is not str or _SIGNATURE.fullmatch(envelope["signature"]) is None:
        raise Refuted("canonical support signature required")
    payload = _record(envelope["payload"], {"schema_version", "selection_digest", "requirement_id", "purpose", "source_id",
        "subject_id", "object_digest", "binding_digest", "scope", "clock_id", "valid_from", "valid_until", "issued_at", "witness"}, "support payload")
    expected = {"schema_version": SUPPORT_VERSION, "selection_digest": claim_selection_digest(request),
        "requirement_id": row["requirement_id"], "purpose": row["purpose"], "source_id": row["source_id"],
        "subject_id": request["subject_id"], "object_digest": request["object_digest"], "binding_digest": request["binding_digest"],
        "clock_id": request["clock_id"]}
    if binding is not None:
        expected["scope"] = binding["scope"]
    else:
        missing.append("supported retained binding absent")
    if any(payload[k] != v for k, v in expected.items()):
        raise Refuted("support independent claim binding differs")
    if not all(_time(payload[k]) for k in ("valid_from", "valid_until", "issued_at")) or payload["valid_from"] >= payload["valid_until"]:
        raise Refuted("support time shape")
    times = [request["evaluation_at"]]
    if presentations is None:
        missing.append("supported presentation inventory absent")
    else:
        if any(type(item) is not dict or not _time(item.get("at")) for item in presentations):
            raise Refuted("presentation plain time differs")
        times.extend(item["at"] for item in presentations)
    if row["purpose"] == "exit_grant":
        times.append(request["exit_probe_at"])
    if not all(payload["valid_from"] <= t < payload["valid_until"] for t in times):
        raise Refuted("support interval does not cover selected times")
    if payload["issued_at"] > min(times) or any(t - payload["issued_at"] > policy["max_support_age"] for t in times):
        raise Refuted("support issue time/freshness differs")
    if source is None:
        missing.append("independently configured source absent")
    else:
        if row["purpose"] in PURPOSES and (row["purpose"] not in source["purposes"]
                or payload["scope"] not in source["scopes"] or request["clock_id"] != source["clock_id"]):
            raise Refuted("configured source lacks required purpose/scope/clock")
        if not all(source["valid_from"] <= t < source["valid_until"] for t in times):
            raise Refuted("source interval does not cover selected times")
        if source["public_key"] is None:
            missing.append("configured source public key absent")
    purpose = row["purpose"]
    witness = payload["witness"]
    wanted = {}
    fields = None
    if purpose == "enrollment_authority":
        if row["expected_value"] != "ENROLL_IDENTITY":
            missing.append("selected enrollment authority action not implemented")
        else:
            fields = {"action", "actor_id", "role_id", "enrollment_id"}
            wanted = {"action": "ENROLL_IDENTITY", "enrollment_id": row["claim_id"]}
            if binding is not None:
                wanted.update(actor_id=binding["actor_id"], role_id=binding["role_id"])
            events = None if lifecycle is None else lifecycle["events"]
            if (type(events) is list and events and type(events[0]) is dict
                    and events[0].get("schema_version") == identity_lifecycle_replay.EVENT_VERSION
                    and events[0].get("kind") in ("enrollment", "handover_in")):
                first = events[0]
                enrollment_id = first["payload"]["enrollment_id"] if first["kind"] == "enrollment" else first["event_id"]
                if row["claim_id"] != enrollment_id:
                    raise Refuted("enrollment requirement belongs to another enrollment")
                wanted["enrollment_id"] = enrollment_id
            else:
                missing.append("supported retained enrollment unavailable")
    elif purpose == "assurance":
        if binding is not None and row["claim_id"] != binding["assurance_requirement_id"]:
            raise Refuted("assurance requirement belongs to another binding")
        if row["expected_value"] != ASSURANCE:
            missing.append("selected assurance method is not installed")
        else:
            fields = {"assurance_id", "method", "native_identity_scope_certificate_ref"}
            wanted = {"assurance_id": row["claim_id"], "method": ASSURANCE,
                      "native_identity_scope_certificate_ref": request["identity_scope_certificate_ref"]}
    elif purpose == "attribute":
        if binding is not None:
            if row["claim_id"] not in binding["relied_attribute_ids"]:
                raise Refuted("foreign attribute requirement")
            if row["source_id"] in (binding["actor_id"], binding["representation_id"], binding["root_human_id"]):
                raise Refuted("attribute source is configured self assertion")
        if (source is not None and source["public_key"] is not None and policy["holder_public_key"] is not None
                and source["public_key"] == policy["holder_public_key"]):
            raise Refuted("attribute source is configured self assertion")
        fields = {"attribute_id", "subject_id", "value"}
        wanted = {"attribute_id": row["claim_id"], "value": row["expected_value"]}
        if binding is not None:
            wanted["subject_id"] = binding["representation_id"]
    elif purpose == "status":
        if row["expected_value"] != "ACTIVE":
            missing.append("selected relying status predicate not implemented")
        else:
            fields = {"state", "head_digest", "event_count"}
            child = request["identity_lifecycle_request"]
            wanted = {"state": "ACTIVE"}
            for field, selection in (("head_digest", "selected_head_digest"), ("event_count", "selected_event_count")):
                if child[selection] is None:
                    missing.append("independently selected status " + field + " absent")
                else:
                    wanted[field] = child[selection]
    elif purpose == "simulation_scope":
        if binding is not None and binding["represented_kind"] != "BOT":
            raise Refuted("SIM prerequisite on non-BOT")
        if row["expected_value"] != "ACTIVE":
            missing.append("selected simulation status predicate not implemented")
        else:
            fields = {"state", "simulation_id", "simulation_record_digest", "scope"}
            wanted = {"state": "ACTIVE", "scope": payload["scope"]}
            if binding is not None:
                wanted.update(simulation_id=binding["simulation_id"], simulation_record_digest=binding["simulation_record_digest"])
    elif purpose == "exit_grant":
        if row["expected_value"] != CONTROL:
            missing.append("selected terminal controller not installed")
        else:
            fields = {"controller_id", "holder_id", "holder_public_key", "probe_ref"}
            wanted = {"controller_id": CONTROL, "holder_id": policy["holder_id"],
                      "holder_public_key": policy["holder_public_key"], "probe_ref": probe_ref}
    else:
        missing.append("unsupported selected support purpose")
    if fields is not None:
        witness = _record(witness, fields, "support witness")
        if any(canonical_bytes(witness[k]) != canonical_bytes(v) for k, v in wanted.items()):
            raise Refuted("native support predicate witness differs")
    if missing:
        raise Unavailable("; ".join(missing))
    if verify:
        _verify_signature(source["public_key"], envelope["signature"], support_signing_bytes(envelope["source_id"], envelope["key_id"], payload))


def _exit_probe(probe: Any, request: dict[str, Any], policy: dict[str, Any], lifecycle: dict[str, Any] | None,
                *, verify: bool = True) -> dict[str, Any]:
    probe = _record(probe, {"schema_version", "selection_digest", "binding_digest", "head_digest", "holder_id", "clock_id",
        "at", "challenge_digest", "controller_id", "signature"}, "terminal probe")
    expected = {"schema_version": PROBE_VERSION, "selection_digest": claim_selection_digest(request),
        "binding_digest": request["binding_digest"],
        "holder_id": policy["holder_id"], "clock_id": request["clock_id"], "at": request["exit_probe_at"],
        "challenge_digest": request["exit_challenge_digest"], "controller_id": CONTROL}
    if request["identity_lifecycle_request"]["selected_head_digest"] is not None:
        expected["head_digest"] = request["identity_lifecycle_request"]["selected_head_digest"]
    if any(probe[k] != v for k, v in expected.items()):
        raise Refuted("terminal holder/controller/probe binding differs")
    if not _time(probe["at"]) or probe["at"] < request["evaluation_at"]:
        raise Refuted("probe precedes relying selection")
    if type(probe["signature"]) is not str or _SIGNATURE.fullmatch(probe["signature"]) is None:
        raise Refuted("canonical holder signature required")
    _hash(probe["head_digest"])
    binding = None if lifecycle is None else lifecycle["binding"]
    if binding is not None:
        expected_holder = binding["representation_id"] if binding["represented_kind"] == "HUMAN" else binding["root_human_id"]
        if policy["holder_id"] != expected_holder:
            raise Refuted("configured holder differs from retained binding")
    if request["identity_lifecycle_request"]["selected_head_digest"] is None:
        raise Unavailable("independently selected terminal head absent")
    if binding is None:
        raise Unavailable("supported retained holder binding absent")
    if policy["holder_public_key"] is None:
        raise Unavailable("configured holder public key absent")
    if not verify:
        return {"declared_probe_predicates": True, "authentication": "NOT_ESTABLISHED"}
    events, rows = lifecycle["events"], lifecycle["presentations"]
    if type(events) is not list or not events or type(rows) is not list:
        raise Unavailable("complete retained terminal interpreter inputs absent")
    _verify_signature(policy["holder_public_key"], probe["signature"], probe_signing_bytes(probe))
    ref = _digest(probe)
    kind = "human_exit" if binding["represented_kind"] == "HUMAN" else "revocation"
    rule = _digest({"controller_id": CONTROL, "mechanism_digest": policy["mechanism_digest"], "holder_public_key": policy["holder_public_key"]})
    payload = {"exit_request_ref": ref, "exit_control_rule_digest": rule[7:]} if kind == "human_exit" else {"revocation_id": "configured-root-withdrawal-probe", "reason_ref": ref}
    appended = {"schema_version": identity_lifecycle_replay.EVENT_VERSION, "event_id": "configured-terminal-probe-" + request["exit_challenge_digest"][7:],
        "position": len(events), "binding_digest": request["binding_digest"][7:], "previous_event_digest": _digest(events[-1])[7:],
        "kind": kind, "at": probe["at"], "payload": payload, "authority_evidence_ref": ref}
    augmented = events + [appended]
    child = request["identity_lifecycle_request"]
    replay = identity_lifecycle_replay.replay_declared_identity_lifecycle(binding, augmented, rows,
        expected_binding_digest=request["binding_digest"][7:], expected_events_digest=_digest(augmented)[7:],
        expected_presentations_digest=request["presentation_inventory_digest"][7:], initial_event_anchor=child["initial_event_anchor"][7:],
        evaluation_at=probe["at"], renewal_ceiling=child["renewal_ceiling"], max_events=child["limits"]["max_events"],
        max_presentations=child["limits"]["max_presentations"], max_steps=child["limits"]["max_steps"])
    if replay.get("checking_unavailable"):
        unavailable = IdentityPresentationUnavailable("actual terminal interpreter checking capacity unavailable")
        if replay["consistency_status"] == "FAIL":
            raise Refuted("fixed terminal interpreter retained an evaluated refutation") from unavailable
        raise unavailable
    if replay["consistency_status"] == "UNKNOWN":
        raise Unavailable("bounded terminal controller replay incomplete")
    if replay["consistency_status"] != "PASS" or replay["declared_reliance_eligibility"] != "FAIL":
        raise Refuted("fixed configured terminal controller failed to terminate binding")
    return {"controller_id": CONTROL, "terminated": True, "represented_entity_termination": "NOT_ESTABLISHED",
            "actual_enforcement": "NOT_ESTABLISHED", "replay": replay}


def _declared_replay(lifecycle: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    child = request["identity_lifecycle_request"]
    return identity_lifecycle_replay.replay_declared_identity_lifecycle(
        lifecycle["binding"], lifecycle["events"], lifecycle["presentations"],
        expected_binding_digest=request["binding_digest"][7:], expected_events_digest=child["events_digest"][7:],
        expected_presentations_digest=request["presentation_inventory_digest"][7:],
        initial_event_anchor=None if child["initial_event_anchor"] is None else child["initial_event_anchor"][7:],
        evaluation_at=request["evaluation_at"],
        renewal_ceiling=child["renewal_ceiling"], max_events=child["limits"]["max_events"],
        max_presentations=child["limits"]["max_presentations"], max_steps=child["limits"]["max_steps"])


def _retained_context(value: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Necessary declared companions, never carried native/authentication credit."""
    raw = value["identity_lifecycle_certificate"]
    if raw is None:
        raise Unavailable("retained native lifecycle certificate absent")
    raw = _record(raw, {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
        "evidence_refs", "evidence_payloads", "result", "digest"}, "retained lifecycle certificate")
    child = request["identity_lifecycle_request"]
    if raw["schema_version"] != identity_lifecycle.CERTIFICATE_VERSION or canonical_bytes(raw["request"]) != canonical_bytes(child):
        raise Refuted("retained lifecycle envelope/request selection differs")
    payloads = raw["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) - {child["evidence_ref"]} or any(type(v) is not str for v in payloads.values()):
        raise Refuted("retained lifecycle payload inventory differs")
    lifecycle = _lifecycle_evidence(raw, child)
    binding, events, rows = lifecycle["binding"], lifecycle["events"], lifecycle["presentations"]
    for item, selected in ((binding, request["binding_digest"]), (events, child["events_digest"]),
                           (rows, request["presentation_inventory_digest"])):
        if item is not None and _digest(item) != selected:
            raise Refuted("retained declared component pin differs")
    if events is not None:
        if type(events) is not list:
            raise Refuted("retained event inventory shape differs")
        if len(events) > child["limits"]["max_events"]:
            raise Unavailable("selected retained event count bound exhausted")
        if ((child["selected_event_count"] is not None and len(events) != child["selected_event_count"])
                or (events and child["selected_head_digest"] is not None and _digest(events[-1]) != child["selected_head_digest"])):
            raise Refuted("independently selected lifecycle head/count differs")
    # Only the installed binding/presentation vocabulary is interpreted below.
    # These contexts permit necessary refutations; actual native replay is separate.
    if binding is not None:
        binding = _record(binding, identity_lifecycle_replay.BINDING_FIELDS, "retained binding")
        if binding["schema_version"] != identity_lifecycle_replay.BINDING_VERSION:
            binding = None
        else:
            ids = ("identity_id", "actor_id", "representation_id", "root_human_id", "role_id", "collective_id",
                   "clock_id", "assurance_requirement_id", "revocation_policy_id")
            if (binding["represented_kind"] not in ("HUMAN", "AGENT", "BOT") or any(not _text(binding[k]) for k in ids)
                    or type(binding["scope"]) is not str or not binding["scope"].strip() or len(binding["scope"]) > 4096):
                raise Refuted("supported retained binding identifiers differ")
            attrs = binding["relied_attribute_ids"]
            if type(attrs) is not list or any(not _text(x) for x in attrs) or len(attrs) != len(set(attrs)):
                raise Refuted("supported retained attribute inventory differs")
            if len(attrs) > 256:
                raise Unavailable("retained attribute bound exhausted")
            if (binding["clock_id"] != request["clock_id"] or binding["identity_id"] != request["subject_id"]
                    or binding["identity_record_digest"] != request["object_digest"][7:]
                    or binding["collective_id"] != request["identity_scope_request"]["collective_id"]):
                raise Refuted("supported retained binding selected subject/record/collective/clock differs")
            if not (_time(binding["valid_from"]) and _time(binding["valid_until"])
                    and binding["valid_from"] < binding["valid_until"] <= child["renewal_ceiling"]):
                raise Refuted("supported retained binding validity differs")
            if binding["represented_kind"] == "BOT":
                if (not _text(binding["simulation_id"])
                        or type(binding["simulation_record_digest"]) is not str
                        or _KEY.fullmatch(binding["simulation_record_digest"]) is None
                        or binding["scope"] != "simulation:" + binding["simulation_id"]):
                    raise Refuted("supported retained BOT scope/SIM differs")
            elif binding["simulation_id"] is not None or binding["simulation_record_digest"] is not None:
                raise Refuted("supported retained non-BOT SIM fields differ")
            exit_policy_ok = (_text(binding["human_exit_policy_id"]) if binding["represented_kind"] == "HUMAN"
                              else binding["human_exit_policy_id"] is None)
            if not exit_policy_ok:
                raise Refuted("supported retained HUMAN exit policy differs")
    if rows is not None:
        if type(rows) is not list:
            raise Refuted("retained presentation inventory shape differs")
        if len(rows) > child["limits"]["max_presentations"]:
            raise Unavailable("selected retained presentation count bound exhausted")
        supported = []
        for item in rows:
            item = _record(item, identity_lifecycle_replay.PRESENTATION_FIELDS, "retained presentation")
            if item["schema_version"] != identity_lifecycle_replay.PRESENTATION_VERSION:
                continue
            if not _time(item["at"]) or item["binding_digest"] != request["binding_digest"][7:] or item["clock_id"] != request["clock_id"]:
                raise Refuted("supported retained presentation selected binding/time/clock differs")
            if binding is not None and (item["scope"] != binding["scope"] or item["simulation_id"] != binding["simulation_id"]):
                raise Refuted("supported retained presentation binding scope/SIM differs")
            supported.append(item)
        rows = supported  # Unsupported rows grant no facts; helper/native completion remains independently required.
    try:
        facts = _declared_replay(lifecycle, request)
    except (OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        facts = {"consistency_status": "UNKNOWN", "checking_unavailable": True,
                 "reason": "actual declared interpreter unavailable: " + type(exc).__name__}
    return {"lifecycle": {**lifecycle, "binding": binding, "presentations": rows},
            "binding": binding, "presentations": rows, "declared": facts}


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    observations: dict[str, Any] = {"components": []}
    statuses: list[str] = []
    operations = 0
    def take() -> None:
        nonlocal operations
        if operations + 1 > request["limits"]["max_operations"]:
            raise Unavailable("selected prerequisite operation bound exhausted; remaining phases unrun")
        operations += 1
    def unavailable(exc: BaseException) -> None:
        if not isinstance(exc, Unavailable):
            observations["unavailable_execution"] = "retained checking unavailable: " + type(exc).__name__
    def component(name: str, action) -> Any:
        try:
            take()
            result = action()
            status = "PASS"
        except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
            unavailable(exc)
            result, status = None, "UNKNOWN"
            observations["components"].append({"name": name, "status": status, "reason": type(exc).__name__})
            statuses.append(status)
            return result
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            if isinstance(exc.__cause__, IdentityPresentationUnavailable):
                unavailable(exc.__cause__)
            if not isinstance(exc, Refuted):
                observations["semantic_refutation"] = "semantic checking refusal occurred"
            result, status = None, "FAIL"
            observations["components"].append({"name": name, "status": status, "reason": type(exc).__name__})
            statuses.append(status)
            return result
        except Exception as exc:
            observations["unavailable_execution"] = "retained checking unavailable: " + type(exc).__name__
            result, status = None, "UNKNOWN"
            observations["components"].append({"name": name, "status": status, "reason": type(exc).__name__})
            statuses.append(status)
            return result
        statuses.append(status)
        observations["components"].append({"name": name, "status": status})
        return result
    try:
        take()
        _retained_preflight(data, request["limits"]["max_evidence_bytes"])
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "identity_scope_certificate",
            "identity_lifecycle_certificate", "supports", "exit_probe"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("canonical prerequisite evidence version differs")
        supports = value["supports"]
        if type(supports) is not dict or any(type(k) is not str for k in supports):
            raise Refuted("support inventory shape differs")
        requirements = policy["requirements"]
        if len(supports) > request["limits"]["max_supports"] or len(requirements) > request["limits"]["max_supports"]:
            raise Unavailable("selected support bound exhausted; verification unrun")
        known = {row["requirement_id"] for row in requirements}
        if set(supports) - known:
            raise Refuted("candidate supplies unselected support")
        # All present independent byte pins and outer shapes precede child calls.
        for name in ("identity_scope", "identity_lifecycle"):
            raw = value[name + "_certificate"]
            if raw is not None:
                _record(raw, {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
                    "evidence_refs", "evidence_payloads", "result", "digest"}, "native child envelope")
                if _digest(raw) != request[name + "_certificate_ref"]:
                    raise Refuted("native child byte pin differs")
        for rid, raw in supports.items():
            _record(raw, {"schema_version", "source_id", "key_id", "payload", "signature"}, "support envelope")
            if rid in request["support_refs"]:
                if _digest(raw) != request["support_refs"][rid]:
                    raise Refuted("selected support byte pin differs")
            else:
                statuses.append("UNKNOWN")
                observations.setdefault("missing_support_byte_pins", []).append(rid)
        probe = value["exit_probe"]
        if probe is not None:
            _record(probe, {"schema_version", "selection_digest", "binding_digest", "head_digest", "holder_id", "clock_id",
                "at", "challenge_digest", "controller_id", "signature"}, "terminal probe")
            if _digest(probe) != request["exit_probe_ref"]:
                raise Refuted("terminal probe byte pin differs")
        context = component("retained_declared_predicates", lambda: _retained_context(value, request))
        binding = None if context is None else context["binding"]
        rows = None if context is None else context["presentations"]
        lifecycle = None if context is None else context["lifecycle"]
        if context is not None:
            observations["retained_declared_lifecycle"] = context["declared"]
            if context["declared"]["consistency_status"] != "PASS":
                statuses.append(context["declared"]["consistency_status"])
            if context["declared"].get("checking_unavailable"):
                observations["unavailable_execution"] = "actual retained declared interpreter capacity unavailable"
            declared = context["declared"]
            if (declared.get("declared_reliance_eligibility") == "FAIL"
                    or any(x["declared_binding_eligibility"] == "FAIL" for x in declared.get("presentation_results", []))):
                statuses.append("FAIL")
                observations["declared_eligibility_failure"] = "supported current/presentation prerequisite refuted"
        sources = {row["source_id"]: row for row in policy["sources"]}
        # Inspect every present required predicate before missing keys/backends.
        for row in requirements:
            def inspect(row=row):
                rid = row["requirement_id"]
                if rid not in supports:
                    raise Unavailable("selected required support absent")
                _support(supports[rid], row, sources.get(row["source_id"]), request, policy,
                         binding, rows, lifecycle, request["exit_probe_ref"], verify=False)
                if rid not in request["support_refs"]:
                    raise Unavailable("selected required support byte pin absent")
                return {"necessary_declared_predicates": True, "authentication": "NOT_ESTABLISHED"}
            component("support_predicates:" + row["requirement_id"], inspect)
        if binding is not None:
            purposes = {row["purpose"] for row in requirements}
            needed = {"enrollment_authority", "assurance", "status", "exit_grant"}
            if binding["represented_kind"] == "BOT":
                needed.add("simulation_scope")
            if needed - purposes:
                statuses.append("UNKNOWN")
                observations["missing_required_purposes"] = sorted(needed - purposes)
            attributes = [row["claim_id"] for row in requirements if row["purpose"] == "attribute"]
            if sorted(attributes) != sorted(binding["relied_attribute_ids"]):
                if set(attributes) - set(binding["relied_attribute_ids"]) or len(attributes) != len(set(attributes)):
                    raise Refuted("foreign/duplicate relied attribute requirements")
                statuses.append("UNKNOWN")
                observations["missing_attributes"] = sorted(set(binding["relied_attribute_ids"]) - set(attributes))
        if probe is None:
            component("terminal_probe_predicates", lambda: (_ for _ in ()).throw(Unavailable("signed holder probe absent")))
        else:
            component("terminal_probe_predicates", lambda: _exit_probe(probe, request, policy, lifecycle, verify=False))
        # Actual cryptography remains purpose-specific and optional; syntax alone
        # and successful declared predicates never establish authentication.
        for row in requirements:
            def signature(row=row):
                rid = row["requirement_id"]
                source = sources.get(row["source_id"])
                if rid not in supports or rid not in request["support_refs"] or source is None or source["public_key"] is None:
                    raise Unavailable("retained configured source/key/pin absent")
                envelope = supports[rid]
                if envelope["source_id"] != source["source_id"] or envelope["key_id"] != source["key_id"]:
                    raise Refuted("configured signature source/key differs")
                _verify_signature(source["public_key"], envelope["signature"],
                                  support_signing_bytes(envelope["source_id"], envelope["key_id"], envelope["payload"]))
                return {"retained_public_key_replay": True}
            component("support_signature:" + row["requirement_id"], signature)
        def holder_signature():
            if probe is None or policy["holder_public_key"] is None:
                raise Unavailable("retained holder key/probe absent")
            _verify_signature(policy["holder_public_key"], probe["signature"], probe_signing_bytes(probe))
            return {"retained_holder_public_key_replay": True}
        component("terminal_probe_signature", holder_signature)
        def child(kind):
            name = "identity_scope" if kind == 3 else "identity_lifecycle"
            raw = value[name + "_certificate"]
            if raw is None:
                raise Unavailable("required native child absent")
            checker = identity_scope.recheck_identity_scope_certificate if kind == 3 else identity_lifecycle.recheck_identity_lifecycle_certificate
            result = checker(canonical_bytes(raw), expected_request=request[name + "_request"], policy=policy[name + "_policy"])
            if result["status"] == "UNKNOWN":
                raise Unavailable("actual native child incomplete")
            if result["status"] != "PASS":
                raise Refuted("actual native child refutes prerequisite")
            return result
        child3 = component("native_identity3", lambda: child(3))
        child2 = component("native_identity2", lambda: child(2))
        def eligible():
            if child2 is None or child3 is None or context is None or context["declared"]["consistency_status"] != "PASS":
                raise Unavailable("actual native children and declared replay completion required")
            facts = child2["evaluation"]["observations"]["declared_lifecycle"]
            if not rows:
                raise Unavailable("nonempty externally selected presentation inventory required")
            if facts["declared_reliance_eligibility"] != "PASS" or any(x["declared_binding_eligibility"] != "PASS" for x in facts["presentation_results"]):
                raise Refuted("current/presentation binding not eligible under retained history")
            return {"actual_native_prerequisites": True}
        eligibility = component("presentation_eligibility", eligible)
        def terminal():
            if eligibility is None or probe is None or lifecycle is None:
                raise Unavailable("actual native prerequisites/probe unavailable; terminal replay unrun")
            return _exit_probe(probe, request, policy, lifecycle)
        exit_result = component("terminal_controller", terminal)
        if exit_result is not None:
            observations["terminal_controller"] = exit_result
        if policy["public_proof_mode"] != PUBLIC_MODE:
            component("public_witness_mode", lambda: (_ for _ in ()).throw(Unavailable("selected public proof mode not implemented")))
        else:
            component("public_witness_mode", lambda: {"mode": PUBLIC_MODE, "all_artifacts_retained": True})
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        unavailable(exc)
        statuses.append("UNKNOWN")
        observations["stopped"] = type(exc).__name__
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        observations["semantic_refutation"] = "evaluated malformed or contradictory retained prerequisite"
        statuses.append("FAIL")
        observations["stopped"] = type(exc).__name__
    except Exception as exc:
        observations["unavailable_execution"] = "retained checking unavailable: " + type(exc).__name__
        statuses.append("UNKNOWN")
        observations["stopped"] = type(exc).__name__
    observations["operations"] = operations
    status = "FAIL" if "FAIL" in statuses else ("UNKNOWN" if "UNKNOWN" in statuses or not statuses else "PASS")
    return MechanismDecision(MechanismOutcome(status), "finite configured identity presentation prerequisite replay", observations)


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": _digest(request), "proposition_digest": PROPOSITION_DIGEST}


class _IdentityPresentationMechanism:
    mechanism_id = MECHANISM_ID
    def __init__(self, request: dict[str, Any], policy: dict[str, Any]):
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]
    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request) or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "exact native prerequisite binding differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one complete retained prerequisite bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _binding(request: dict[str, Any], policy: dict[str, Any]) -> BoundProposition:
    return BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))


def _retained_claims(value: dict[str, Any], request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> None:
    """Refuse independent carried claim/binding contradictions before replay."""
    for field, expected in (("policy_digest", request["policy_digest"]), ("mechanism_digest", policy["mechanism_digest"]),
                            ("proposition_digest", PROPOSITION_DIGEST), ("evidence_refs", [request["evidence_ref"]])):
        if value[field] != expected:
            raise IdentityPresentationError("retained envelope selection differs: " + field)
    exclusions = ("real_issuer_authority", "human_authenticity", "actor_independence", "live_clock",
                  "physical_exit_enforcement", "global_public_availability", "privacy_consent_admission",
                  "whole_identity_closure", "object_profile_conformance")
    result = _record(value["result"], {"status", "semantic_version", "coordinate", "object_kind", "scope", "evaluation",
        "configured_public_witness_mode", *exclusions}, "retained result")
    for field, expected in (("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE), ("object_kind", "IDENTITY"),
                            ("scope", SCOPE), ("configured_public_witness_mode", policy["public_proof_mode"]),
                            *((field, "NOT_ESTABLISHED") for field in exclusions)):
        if type(result[field]) is not str or result[field] != expected:
            raise IdentityPresentationError("retained result claim boundary differs: " + field)
    if type(result["status"]) is not str or result["status"] not in ("PASS", "FAIL", "UNKNOWN"):
        raise IdentityPresentationError("retained result status differs")
    evaluation = _record(result["evaluation"], {"binding_digest", "outcome", "mechanism_id", "mechanism_digest", "evidence_refs",
        "trust_roots", "observed_evidence_bytes", "details", "observations"}, "retained evaluation")
    for field, expected in (("binding_digest", _binding(request, policy).digest()), ("outcome", result["status"]),
                            ("mechanism_id", MECHANISM_ID), ("mechanism_digest", policy["mechanism_digest"]),
                            ("evidence_refs", [request["evidence_ref"]]), ("trust_roots", policy["trust_roots"])):
        if evaluation[field] != expected:
            raise IdentityPresentationError("retained evaluation selection differs: " + field)
    expected_size = len(store.resolve(request["evidence_ref"])) if request["evidence_ref"] in store else 0
    if (type(evaluation["observed_evidence_bytes"]) is not int or evaluation["observed_evidence_bytes"] != expected_size
            or type(evaluation["details"]) is not str or type(evaluation["observations"]) is not dict):
        raise IdentityPresentationError("retained evaluation shape differs")
    if _hash(value["digest"]) != _digest({k: v for k, v in value.items() if k != "digest"}):
        raise IdentityPresentationError("retained certificate digest differs")


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    session = VerificationSession(store)
    session.register(_IdentityPresentationMechanism(request, policy))
    evaluation = session.evaluate(_binding(request, policy))
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "IDENTITY", "scope": SCOPE, "evaluation": evaluation.to_dict(),
        "configured_public_witness_mode": policy["public_proof_mode"], "real_issuer_authority": "NOT_ESTABLISHED",
        "human_authenticity": "NOT_ESTABLISHED", "actor_independence": "NOT_ESTABLISHED", "live_clock": "NOT_ESTABLISHED",
        "physical_exit_enforcement": "NOT_ESTABLISHED", "global_public_availability": "NOT_ESTABLISHED",
        "privacy_consent_admission": "NOT_ESTABLISHED", "whole_identity_closure": "NOT_ESTABLISHED", "object_profile_conformance": "NOT_ESTABLISHED"}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = _digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise IdentityPresentationUnavailable("certificate byte bound exhausted")
    return encoded


def _selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    # Capture both before any installed source reader or child validation.
    raw_request, raw_policy = _capture(request), _capture(policy)
    try:
        admitted = _policy(raw_policy)
        return _request(raw_request, admitted), admitted
    except (OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("selected native source checking unavailable") from exc


def build_identity_presentation_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _selection(request, policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes:
            raise IdentityPresentationError("immutable prerequisite evidence required")
        if len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise IdentityPresentationUnavailable("retained prerequisite evidence byte bound exhausted")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise IdentityPresentationError("retained evidence differs from external selection")
    try:
        return _build(selected, admitted, store)
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("retained certificate construction capacity unavailable") from exc


def recheck_identity_presentation_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _selection(expected_request, policy)
    if type(certificate_bytes) is not bytes:
        raise IdentityPresentationError("immutable certificate required")
    if len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise IdentityPresentationUnavailable("selected certificate byte checking bound exhausted")
    try:
        _retained_preflight(certificate_bytes, admitted["max_certificate_bytes"])
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest",
            "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (value["schema_version"] != CERTIFICATE_VERSION or canonical_bytes(value) != certificate_bytes
                or canonical_bytes(value["request"]) != canonical_bytes(selected)):
            raise IdentityPresentationError("canonical certificate or selected request differs")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or set(payloads) - {selected["evidence_ref"]} or any(type(v) is not str for v in payloads.values()):
            raise IdentityPresentationError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        _retained_claims(value, selected, admitted, store)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            reproduced = strict_json_loads(rebuilt.decode("utf-8"))["result"]
            fresh = reproduced["evaluation"]["observations"]
            if (fresh.get("unavailable_execution") and not fresh.get("semantic_refutation")
                    and (reproduced["status"] == "UNKNOWN" or reproduced["status"] == value["result"]["status"] == "FAIL")):
                raise IdentityPresentationUnavailable("native recheck unavailable; evaluated " + reproduced["status"]
                    + " retained, exact certificate reproduction unestablished")
            raise IdentityPresentationError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, OSError, ImportError, CancelledError, RecursionError, OverflowError) as exc:
        raise IdentityPresentationUnavailable("retained native checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, IdentityPresentationError):
            raise
        raise IdentityPresentationError("invalid prerequisite certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "SCOPE", "PROPOSITION", "PROPOSITION_DIGEST", "REQUEST_VERSION",
    "POLICY_VERSION", "EVIDENCE_VERSION", "CERTIFICATE_VERSION", "IdentityPresentationError", "IdentityPresentationUnavailable", "ROUTE_DESCRIPTOR", "registration", "identity_presentation_policy",
    "identity_presentation_request", "claim_selection_digest", "support_signing_bytes", "probe_signing_bytes",
    "build_identity_presentation_certificate", "recheck_identity_presentation_certificate"]
