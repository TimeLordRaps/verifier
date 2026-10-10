"""Portable finite ten-tier VERIFIER-10.1 replacement replay.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8). Ed25519 is the Edwards-curve
digital signature algorithm with a 255-bit field. Byte bounds count octets;
epochs, generations and event counts are dimensionless. This checker replays
retained observations, never callbacks. Explicit consumer admission selects
keys, source closure and coverage; signatures alone do not supply admission.
A finite PASS supplies neither whole corrigibility nor production acceptance.
"""
from __future__ import annotations

from asyncio import CancelledError
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core import signature_keys as signature_keys_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.receipt import strict_json_loads
from verifier.core.namespace import NamespaceObject
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection
from verifier.runtime import permission_slot

SEMANTIC_VERSION = "verifier-current-ten-tier-object-obligations-1"
COORDINATE = "VERIFIER-10.1"
REQUEST_VERSION = "verifier-ten-tier-verifier-replacement-request-1"
POLICY_VERSION = "verifier-ten-tier-verifier-replacement-policy-1"
EVIDENCE_VERSION = "verifier-ten-tier-verifier-replacement-evidence-1"
CERTIFICATE_VERSION = "verifier-ten-tier-verifier-replacement-certificate-1"
CONTEXT_VERSION = "verifier-ten-tier-verifier-replacement-context-1"
SELECTOR_VERSION = "verifier-ten-tier-verifier-replacement-selection-1"
ADMISSION_VERSION = "verifier-ten-tier-verifier-replacement-admission-1"
ATTESTATION_VERSION = "verifier-ten-tier-verifier-replacement-attestation-1"
AUTHORITY_VERSION = "verifier-ten-tier-verifier-replacement-authority-1"
OBSERVER_VERSION = "verifier-ten-tier-verifier-replacement-observer-1"
EXECUTION_VERSION = "verifier-ten-tier-verifier-replacement-execution-closure-1"
MECHANISM_ID = "verifier.ten-tier.verifier.selected-replacement.1"
SCOPE = "finite_selected_observed_replacement"
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_SELECTION_BYTES = 1024 * 1024
_MAX_GENERATION = 2**63 - 1
_PREFIX = b"verifier-ten-tier-verifier-replacement-signature-1\x00"
_SELECTION_FIELDS = {
    "artifact_digest", "instruction_digest", "policy_digest", "context_digest",
    "session_id", "process_id", "generation",
}
_TICKET_FIELDS = {"invocation_id", "selection", "permission_digest", "epoch"}
_CENSUS_FIELDS = {"selection", "epoch", "active", "queued", "inflight", "permission_digest", "authority"}
_ENVELOPE_FIELDS = {
    "schema_version", "request", "policy_digest", "mechanism_digest",
    "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
}
_EXCLUDED = (
    "object_profile_conformance", "whole_corrigibility_conformance", "authority",
    "actual_execution", "human_acceptance", "production_admission",
    "availability", "burn_erasure", "trusted_time", "live_revocation",
    "context_consumption", "public_disclosure_authority",
)
_PASS_DETAILS = "exact admitted finite replacement observations reproduce"


class VerifierReplacementError(ValueError):
    """Malformed closed selection or substituted retained certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-ten-tier-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "VERIFIER", "scope": SCOPE,
        "proposition": (
            "Inside the exact externally selected finite host boundary, retained "
            "ordered observations and independently admitted signed authority and "
            "complete effect census evidence reproduce revocation, empty drain, "
            "one separately authorized successor, actual stale callback refusal "
            "and successor entry with exact operation, source, artifact, instruction, "
            "policy, typed context, session, process, generation and effect binding."
        ),
        "prerequisites": [
            "externally selected exact host trace, terminal census and retained byte commitments",
            "independently selected authority and complete effect-observer admission roots",
        ],
        "exclusions": list(_EXCLUDED),
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


class VerifierReplacementDescriptor:
    """Metadata for one finite predicate in the explicit ten-tier family."""
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _plain(value: Any, limit: int = _MAX_SELECTION_BYTES) -> Any:
    state = {"values": 0, "text": 0}

    def visit(item: Any, depth: int) -> Any:
        state["values"] += 1
        if depth > 48 or state["values"] > 150000:
            raise VerifierReplacementError("primitive structural bound exhausted")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > 64:
                raise VerifierReplacementError("primitive integer bound exhausted")
            return item
        if kind is str:
            if len(item) > limit - state["text"]:
                raise VerifierReplacementError("primitive text bound exhausted")
            state["text"] += len(item.encode("utf-8"))
            if state["text"] > limit:
                raise VerifierReplacementError("primitive text bound exhausted")
            return item
        if kind is list:
            if len(item) > 16384:
                raise VerifierReplacementError("primitive item bound exhausted")
            return [visit(child, depth + 1) for child in item]
        if kind is dict:
            if len(item) > 16384 or any(type(key) is not str for key in item):
                raise VerifierReplacementError("plain bounded keys required")
            return {visit(key, depth + 1): visit(child, depth + 1) for key, child in item.items()}
        raise VerifierReplacementError("exact plain primitive values required")

    captured = visit(value, 0)
    if len(canonical_bytes(captured)) > limit:
        raise VerifierReplacementError("primitive byte bound exhausted")
    return captured


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, VerifierReplacementError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, VerifierReplacementError)


def _label(value: Any) -> str:
    if (type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 256
            or any(ord(char) < 32 for char in value)):
        raise VerifierReplacementError("bounded plain identifier required")
    return value


def _integer(value: Any, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise VerifierReplacementError("bounded plain integer required")
    return value


def _hex(value: Any, digits: int) -> str:
    if (type(value) is not str or len(value) != digits
            or any(char not in "0123456789abcdef" for char in value)):
        raise VerifierReplacementError("canonical hexadecimal required")
    return value


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _selection(value: Any) -> dict[str, Any]:
    selected = _record(value, _SELECTION_FIELDS, "selection")
    for key in ("artifact_digest", "instruction_digest", "policy_digest", "context_digest"):
        _digest(selected[key])
    for key in ("session_id", "process_id"):
        _label(selected[key])
    _integer(selected["generation"], 1, _MAX_GENERATION)
    return selected


def context_binding(value: Any) -> dict[str, Any]:
    """Capture typed retained context references without claiming their consumption."""
    selected = _record(_plain(value), {
        "schema_version", "revision_digest", "TIME", "TOKEN", "ENV", "HARDWARE", "SPACE",
    }, "typed context")
    if selected["schema_version"] != CONTEXT_VERSION:
        raise VerifierReplacementError("typed context version differs")
    for key in set(selected) - {"schema_version"}:
        _digest(selected[key])
    return selected


def context_digest(value: Any) -> str:
    return _hash(canonical_bytes(context_binding(value)))


def _mechanism_paths() -> dict[str, Path]:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module,
               common_module, retained_selection, signature_keys_module, permission_slot)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("CURRENT_VERIFIER_REPLACEMENT.md", "CURRENT_PERMISSION_SLOT.md",
                 "CURRENT_TEN_TIER_PROGRESSION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return paths


def _mechanism_bytes() -> bytes:
    return canonical_bytes({
        name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(_mechanism_paths().items())
    })


def mechanism_digest() -> str:
    """Bind exact native and host readers without recursive dispatch registration."""
    return _hash(_mechanism_bytes())


def _keys(value: Any) -> dict[str, str]:
    if type(value) is not dict or not 1 <= len(value) <= 16:
        raise VerifierReplacementError("one to sixteen selected keys required")
    for key, public in value.items():
        _label(key)
        _hex(public, 64)
        signature_keys_module.admit_ed25519_public_key(bytes.fromhex(public))
    if len(set(value.values())) != len(value):
        raise VerifierReplacementError("distinct selected key bytes required; signer aliases are refused")
    return dict(value)


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(_plain(value), {
        "schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "admission_key_id", "admission_public_key",
        "authority_keys", "observer_keys", "authority_admission_digest", "observer_admission_digest",
    }, "policy")
    if selected["schema_version"] != POLICY_VERSION or selected["mechanism_id"] != MECHANISM_ID:
        raise VerifierReplacementError("selected policy mechanism differs")
    _digest(selected["mechanism_digest"])
    _label(selected["admission_key_id"])
    _hex(selected["admission_public_key"], 64)
    signature_keys_module.admit_ed25519_public_key(bytes.fromhex(selected["admission_public_key"]))
    _keys(selected["authority_keys"])
    _keys(selected["observer_keys"])
    for key in ("authority_admission_digest", "observer_admission_digest"):
        _digest(selected[key])
    roots = selected["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise VerifierReplacementError("bounded selected trust roots required")
    for root in roots:
        _label(root)
    if roots != sorted(set(roots)):
        raise VerifierReplacementError("sorted distinct trust roots required")
    _integer(selected["max_certificate_bytes"], 1, _MAX_CERTIFICATE_BYTES)
    return selected


def verifier_replacement_policy(*, trust_roots: list[str], admission_key_id: str,
        admission_public_key: str, authority_keys: dict[str, str], observer_keys: dict[str, str],
        authority_admission_digest: str, observer_admission_digest: str,
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "admission_key_id": admission_key_id, "admission_public_key": admission_public_key,
        "authority_keys": authority_keys, "observer_keys": observer_keys,
        "authority_admission_digest": authority_admission_digest,
        "observer_admission_digest": observer_admission_digest,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _inventory(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 4096:
        raise VerifierReplacementError("bounded selected effect inventory required")
    rows = []
    for item in value:
        row = _record(item, {"invocation_id", "effect_id", "effect_digest", "selection_digest"}, "effect")
        _label(row["invocation_id"])
        _label(row["effect_id"])
        _digest(row["effect_digest"])
        _digest(row["selection_digest"])
        rows.append(row)
    names = [row["invocation_id"] for row in rows]
    if names != sorted(set(names)):
        raise VerifierReplacementError("sorted distinct effect invocation identifiers required")
    return rows


def _request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    selected = _record(_plain(value), {
        "schema_version", "semantic_version", "coordinate", "proposition_digest", "object_kind",
        "subject_id", "object_digest", "collection_digest", "operation_id", "boundary_id",
        "initial", "successor", "execution_closure_digest", "capture_digest", "trace_digest",
        "terminal_sequence", "terminal_census_digest", "revocation_cutoff", "revocation_view_digest",
        "effect_inventory", "evidence_ref", "policy_digest", "max_evidence_bytes", "cancelled",
    }, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "VERIFIER")):
        if selected[field] != expected:
            raise VerifierReplacementError("selected native replacement objective differs")
    for key in ("subject_id", "operation_id", "boundary_id"):
        _label(selected[key])
    for key in ("object_digest", "collection_digest", "execution_closure_digest", "capture_digest",
                "trace_digest", "terminal_census_digest", "revocation_view_digest", "evidence_ref", "policy_digest"):
        _digest(selected[key])
    if selected["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise VerifierReplacementError("selected outer policy differs")
    selected["initial"] = _selection(selected["initial"])
    selected["successor"] = _selection(selected["successor"])
    _integer(selected["terminal_sequence"], 0, 16384)
    _integer(selected["revocation_cutoff"], 1, _MAX_GENERATION)
    _integer(selected["max_evidence_bytes"], 1, _MAX_EVIDENCE_BYTES)
    selected["effect_inventory"] = _inventory(selected["effect_inventory"])
    if type(selected["cancelled"]) is not bool:
        raise VerifierReplacementError("plain explicitly selected cancellation observation required")
    return selected


def verifier_replacement_request(*, subject_id: str, object_digest: str, collection_digest: str,
        operation_id: str, boundary_id: str, initial: dict[str, Any], successor: dict[str, Any],
        execution_closure_digest: str, capture_digest: str, trace_digest: str, terminal_sequence: int,
        terminal_census_digest: str, revocation_cutoff: int, revocation_view_digest: str,
        effect_inventory: list[dict[str, Any]], evidence_ref: str, policy: dict[str, Any],
        cancelled: bool = False, max_evidence_bytes: int = _MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    admitted = _policy(policy)
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind": "VERIFIER",
        "subject_id": subject_id, "object_digest": object_digest, "collection_digest": collection_digest,
        "operation_id": operation_id, "boundary_id": boundary_id, "initial": initial, "successor": successor,
        "execution_closure_digest": execution_closure_digest, "capture_digest": capture_digest,
        "trace_digest": trace_digest, "terminal_sequence": terminal_sequence,
        "terminal_census_digest": terminal_census_digest, "revocation_cutoff": revocation_cutoff,
        "revocation_view_digest": revocation_view_digest, "effect_inventory": effect_inventory,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "max_evidence_bytes": max_evidence_bytes, "cancelled": cancelled,
    }, admitted)


def _json(data: bytes) -> Any:
    depth, containers, digits = 0, 0, 0
    quoted = escaped = False
    for octet in data:
        if quoted:
            if escaped:
                escaped = False
            elif octet == 92:
                escaped = True
            elif octet == 34:
                quoted = False
            continue
        if octet == 34:
            quoted, digits = True, 0
        elif octet in (91, 123):
            depth += 1
            containers += 1
            digits = 0
            if depth > 48 or containers > 150000:
                raise Unavailable("retained decoder structural capacity exhausted")
        elif octet in (93, 125):
            depth -= 1
            digits = 0
        elif 48 <= octet <= 57:
            digits += 1
            if digits > 20:
                raise Unavailable("retained decoder integer capacity exhausted")
        else:
            digits = 0
    return _plain(strict_json_loads(data.decode("utf-8")), _MAX_CERTIFICATE_BYTES)


def _b64(value: Any, limit: int) -> bytes:
    if type(value) is not str:
        raise Refuted("retained payload is not canonical base64")
    if len(value) > 4 * ((limit + 2) // 3):
        raise Unavailable("retained decoded capacity exhausted")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > limit:
        raise Unavailable("retained decoded capacity exhausted")
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refuted("retained payload is noncanonical base64")
    return raw


def verifier_replacement_signing_bytes(payload: dict[str, Any]) -> bytes:
    """Domain-separated signing input; signing and root choice remain external."""
    selected = _plain(payload)
    if type(selected) is not dict or selected.get("schema_version") not in {
            ADMISSION_VERSION, AUTHORITY_VERSION, OBSERVER_VERSION}:
        raise VerifierReplacementError("selected signed payload version differs")
    return _PREFIX + canonical_bytes(selected)


def _verify_signature(public_key: str, signature: str, message: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise Unavailable("optional signature backend unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(signature), message)
    except UnsupportedAlgorithm as exc:
        raise Unavailable("optional signature backend unavailable") from exc
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refuted("selected signed statement does not verify") from exc


def _signed(value: Any, keys: dict[str, str], expected: dict[str, Any]) -> tuple[str, str, bytes]:
    row = _record(value, {"schema_version", "key_id", "payload", "signature"}, "attestation")
    _label(row["key_id"])
    if row["schema_version"] != ATTESTATION_VERSION or row["key_id"] not in keys:
        raise Refuted("signed key differs from externally selected keys")
    _hex(row["signature"], 128)
    if canonical_bytes(row["payload"]) != canonical_bytes(expected):
        raise Refuted("signed statement contradicts selected exact purpose or binding")
    return keys[row["key_id"]], row["signature"], verifier_replacement_signing_bytes(expected)


def _ticket(value: Any) -> dict[str, Any]:
    row = _record(value, _TICKET_FIELDS, "ticket")
    _label(row["invocation_id"])
    _selection(row["selection"])
    _digest(row["permission_digest"])
    _integer(row["epoch"], 1, _MAX_GENERATION)
    return row


def _census(value: Any) -> dict[str, Any]:
    row = _record(value, _CENSUS_FIELDS, "census")
    _selection(row["selection"])
    _integer(row["epoch"], 0, _MAX_GENERATION)
    if type(row["active"]) is not bool:
        raise Refuted("census active flag differs")
    for name in ("queued", "inflight"):
        if type(row[name]) is not list or len(row[name]) > 4096:
            raise Refuted("census inventory differs")
        for ticket in row[name]:
            _ticket(ticket)
        labels = [ticket["invocation_id"] for ticket in row[name]]
        if labels != sorted(set(labels)):
            raise Refuted("census ticket order or uniqueness differs")
    if row["permission_digest"] is not None:
        _digest(row["permission_digest"])
    if row["authority"] is not None:
        _label(row["authority"])
    return row


def _grant_decision(value: Any) -> dict[str, Any]:
    row = _record(value, {"status", "grant", "epoch"}, "grant decision")
    _integer(row["epoch"], 0, _MAX_GENERATION)
    if row["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
        raise Refuted("grant decision status differs")
    grant = _record(row["grant"], {
        "selection", "authority", "permission_digest", "revocation_view_digest", "evidence_digest", "nonce", "purpose",
    }, "grant")
    _selection(grant["selection"])
    for key in ("authority", "nonce"):
        _label(grant[key])
    for key in ("permission_digest", "revocation_view_digest", "evidence_digest"):
        _digest(grant[key])
    if grant["purpose"] not in {"initial", "successor"}:
        raise Refuted("grant purpose differs")
    return row


def _replay(capture: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Independent finite lifecycle interpreter; does not call host producer helpers."""
    old, successor = request["initial"], request["successor"]
    if capture["initial"] != old:
        raise Refuted("retained initial tuple differs")
    if successor["generation"] != old["generation"] + 1 or successor["process_id"] != old["process_id"]:
        raise Refuted("selected successor generation or process differs")
    intent = capture["intent"]
    if intent is not None:
        intent = _record(intent, {"old", "successor", "epoch"}, "intent")
        if intent["old"] != old or intent["successor"] != successor:
            raise Refuted("retained intent tuple differs")
        _integer(intent["epoch"], 0, _MAX_GENERATION)
    result = _record(capture["result"], {
        "status", "reason", "census", "ticket", "scope", "native_corrigibility_conformance",
        "authority_admission", "observer_admission",
    }, "local result")
    if result["status"] == "FAIL":
        raise Refuted("retained producer already reports a failure")
    if (result["status"] not in {"PASS", "UNKNOWN"} or result["ticket"] is not None
            or result["scope"] != "finite-local-permission-slot-controls"
            or result["native_corrigibility_conformance"] != "NOT_ESTABLISHED"
            or result["authority_admission"] != "EXTERNAL_DEPENDENCY"
            or result["observer_admission"] != "EXTERNAL_DEPENDENCY"):
        raise Refuted("local result scope or unsupported admission differs")
    _label(result["reason"])
    census = _census(result["census"])
    events, observations = capture["events"], capture["observations"]
    if type(events) is not list or len(events) > 16384 or type(observations) is not list or len(observations) > 16384:
        raise Refuted("retained lifecycle inventory differs")
    trace_bytes = json.dumps(events, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if (capture["terminal_sequence"] != len(events) or len(events) != request["terminal_sequence"]
            or capture["trace_digest"] != request["trace_digest"] or _hash(trace_bytes) != request["trace_digest"]
            or _hash(canonical_bytes(census)) != request["terminal_census_digest"]):
        raise Refuted("trace or terminal census contradicts external anchors")
    decisions, entries, drains = [], {}, []
    incomplete = result["status"] == "UNKNOWN"
    for item in observations:
        observation = _record(item, {"kind", "record"}, "observation")
        kind, row = observation["kind"], observation["record"]
        if kind == "GrantDecision":
            row = _grant_decision(row)
            if row["status"] == "FAIL":
                raise Refuted("retained grant rejection remains a failure")
            incomplete = incomplete or row["status"] == "UNKNOWN"
            decisions.append(row)
        elif kind == "EntryObservation":
            row = _record(row, {"observer_id", "ticket", "attempts", "entries", "exits", "status"}, "entry observation")
            _label(row["observer_id"])
            ticket = _ticket(row["ticket"])
            for key in ("attempts", "entries", "exits"):
                _integer(row[key], 0, 4096)
            key = ticket["invocation_id"]
            if key in entries or row["status"] == "FAIL":
                raise Refuted("duplicate entry observation or retained observer failure")
            if row["status"] not in {"PASS", "UNKNOWN"}:
                raise Refuted("entry observation status differs")
            incomplete = incomplete or row["status"] != "PASS"
            entries[key] = row
        elif kind == "DrainObservation":
            row = _record(row, {"observer_id", "census", "status"}, "drain observation")
            _label(row["observer_id"])
            _census(row["census"])
            if row["status"] == "FAIL":
                raise Refuted("retained drain failure")
            if row["status"] not in {"PASS", "UNKNOWN"}:
                raise Refuted("drain observation status differs")
            incomplete = incomplete or row["status"] != "PASS"
            drains.append(row)
        else:
            raise Refuted("unknown observation kind")
    epoch, selected, active = 0, old, False
    permission = authority = None
    tickets, counts, pending, queue, entered, cancelled = {}, {}, set(), set(), set(), set()
    admitted_attempts = set()
    grants, nonces, revoked_authorities = [], set(), set()
    cutoff, drained, successor_granted, intent_seen, stale_refused = 0, False, False, False, False
    inventory = {row["invocation_id"]: row for row in request["effect_inventory"]}
    for number, item in enumerate(events, 1):
        event = _record(item, {"sequence", "action", "selection", "epoch", "invocation_id", "ticket"}, "event")
        _selection(event["selection"])
        _integer(event["epoch"], 0, _MAX_GENERATION)
        if type(event["sequence"]) is not int or event["sequence"] != number:
            raise Refuted("retained event sequence differs")
        action, key = event["action"], event["invocation_id"]
        if action in {"initial_grant", "successor_grant"}:
            expected = old if action == "initial_grant" else successor
            purpose = "initial" if action == "initial_grant" else "successor"
            if key != "" or event["ticket"] is not None or event["selection"] != expected or event["epoch"] != epoch + 1 or active:
                raise Refuted("grant transition contradicts selected slot")
            if action == "initial_grant" and (grants or cutoff) or action == "successor_grant" and (successor_granted or not cutoff or not drained or entered or queue or not intent_seen):
                raise Refuted("grant order bypasses revocation or observed drain")
            matching = [row for row in decisions if row["status"] == "PASS" and row["epoch"] == epoch
                        and row["grant"]["selection"] == expected and row["grant"]["purpose"] == purpose]
            unique = {canonical_bytes(row): row for row in matching}
            if len(unique) != 1:
                # Missing activation observation leaves permission/authority
                # unknown, but cannot hide later epoch/selection entry failure.
                incomplete = True
                grant = None
            else:
                decision = next(iter(unique.values()))
                grant = decision["grant"]
                if grant["nonce"] in nonces or grant["authority"] in revoked_authorities:
                    raise Refuted("duplicate nonce or revoked authority grants successor")
                if purpose == "successor" and grant["revocation_view_digest"] != request["revocation_view_digest"]:
                    raise Refuted("successor grant names another selected revocation view")
                nonces.add(grant["nonce"])
                grants.append(decision)
            epoch, selected, active = event["epoch"], expected, True
            permission = grant["permission_digest"] if grant else None
            authority = grant["authority"] if grant else None
            successor_granted = successor_granted or purpose == "successor"
        elif action in {"revoked", "revocation_cutoff_refreshed"}:
            if key != "" or event["ticket"] is not None or event["selection"] != selected or event["epoch"] != epoch + 1:
                raise Refuted("revocation transition binding differs")
            if action == "revoked" and not active or action == "revocation_cutoff_refreshed" and active:
                raise Refuted("revocation activity transition differs")
            if selected != old:
                incomplete = True
            if authority is not None and active:
                revoked_authorities.add(authority)
            cancelled.update(queue)
            queue.clear()
            epoch, active, cutoff, drained = event["epoch"], False, event["epoch"], False
        elif action == "drained":
            if key != "" or event["ticket"] is not None or event["selection"] != selected or event["epoch"] != epoch or active or queue or entered or not cutoff:
                raise Refuted("drain contradicts outstanding selected work")
            if pending & admitted_attempts:
                incomplete = True
            expected_census = {"selection": selected, "epoch": epoch, "active": False, "queued": [],
                               "inflight": [], "permission_digest": permission, "authority": authority}
            matching = [row for row in drains if row["status"] == "PASS"
                        and all(row["census"][name] == expected_census[name]
                                for name in _CENSUS_FIELDS if name not in {"permission_digest", "authority"})
                        and (permission is None or row["census"]["permission_digest"] == permission)
                        and (authority is None or row["census"]["authority"] == authority)]
            if not matching:
                incomplete = True
            if any(row["census"]["epoch"] == epoch and row["census"] != expected_census
                   for row in drains if permission is not None and authority is not None):
                raise Refuted("retained drain observation contradicts exact empty census")
            drained = True
        elif action == "restart_intent":
            if key != "" or event["ticket"] is not None or event["selection"] != selected or event["epoch"] != epoch or intent_seen or intent is None or intent["epoch"] != epoch:
                raise Refuted("restart intent transition differs")
            intent_seen = True
        elif action == "queued":
            ticket = _ticket(event["ticket"])
            if (key != ticket["invocation_id"] or key in tickets or ticket["selection"] != selected
                    or event["selection"] != selected or not active or event["epoch"] != epoch
                    or ticket["epoch"] != epoch or permission is not None and ticket["permission_digest"] != permission):
                raise Refuted("queue ticket differs from active exact selection")
            if key not in inventory:
                incomplete = True
            elif inventory[key]["selection_digest"] != _hash(canonical_bytes(ticket["selection"])):
                raise Refuted("selected effect inventory names another generation")
            tickets[key], counts[key] = ticket, {"attempts": 0, "entries": 0, "exits": 0}
            queue.add(key)
        elif action in {"callback_attempt", "callback_entry", "callback_exit", "callback_refused", "cancel_requested"}:
            if (key not in tickets or event["ticket"] != tickets[key]
                    or event["selection"] != tickets[key]["selection"] or event["epoch"] != epoch):
                raise Refuted("callback event ticket or current epoch differs")
            ticket = tickets[key]
            if action == "callback_attempt":
                if counts[key]["attempts"]:
                    raise Refuted("duplicate callback attempt")
                counts[key]["attempts"] += 1
                queue.discard(key)
                pending.add(key)
                if (active and key not in cancelled and ticket["selection"] == selected
                        and ticket["epoch"] == epoch
                        and (permission is None or ticket["permission_digest"] == permission)):
                    admitted_attempts.add(key)
            elif action == "callback_entry":
                if (key not in pending or key in entered or counts[key]["entries"] or not active
                        or ticket["selection"] != selected or ticket["epoch"] != epoch
                        or permission is not None and ticket["permission_digest"] != permission or key in cancelled):
                    raise Refuted("stale or revoked generation entered an effect")
                counts[key]["entries"] += 1
                entered.add(key)
            elif action == "callback_exit":
                if key not in entered or counts[key]["exits"]:
                    raise Refuted("unbalanced or duplicate callback exit")
                counts[key]["exits"] += 1
                entered.remove(key)
                pending.remove(key)
            elif action == "callback_refused":
                if key not in pending or counts[key]["entries"]:
                    raise Refuted("refusal contradicts actual callback entry")
                if active and ticket["selection"] == selected and ticket["epoch"] == epoch and key not in cancelled:
                    raise Refuted("refusal contradicts active exact permission")
                pending.remove(key)
                stale_refused = stale_refused or ticket["selection"] == old and bool(cutoff) and drained
            else:
                cancelled.add(key)
                queue.discard(key)
        else:
            raise Refuted("unsupported retained transition")
    expected_census = {"selection": selected, "epoch": epoch, "active": active,
                       "queued": [tickets[key] for key in sorted(queue)],
                       "inflight": [tickets[key] for key in sorted(pending)],
                       "permission_digest": permission, "authority": authority}
    # Attempt admission is not a complete lifetime witness. The real host's
    # finally block can release it after cancellation without another event.
    terminal_inflight = {ticket["invocation_id"] for ticket in census["inflight"]}
    if any(key not in tickets or tickets[key] != ticket for key, ticket in ((ticket["invocation_id"], ticket) for ticket in census["inflight"])):
        raise Refuted("terminal census contains an unregistered exact ticket")
    if terminal_inflight - admitted_attempts:
        raise Refuted("terminal census reports inflight work without an actual attempt")
    if pending or entered or terminal_inflight:
        incomplete = True
    terminal_fields = _CENSUS_FIELDS - {"permission_digest", "authority", "inflight"}
    halted_tail = (result["status"] == "UNKNOWN" and census["epoch"] > epoch
                   and not census["active"] and not census["queued"])
    if halted_tail:
        incomplete = True
        terminal_fields -= {"epoch", "active", "queued"}
    if (any(census[name] != expected_census[name] for name in terminal_fields)
            or permission is not None and census["permission_digest"] != permission
            or authority is not None and census["authority"] != authority
            or cutoff != request["revocation_cutoff"]):
        raise Refuted("terminal census or selected revocation cutoff differs")
    for key, row in entries.items():
        if key not in tickets or row["ticket"] != tickets[key]:
            raise Refuted("retained entry observation contradicts replayed transitions")
        mismatches = [name for name in ("attempts", "entries", "exits") if row[name] != counts[key][name]]
        if mismatches:
            if halted_tail and all(counts[key][name] <= row[name] <= 1 for name in mismatches):
                incomplete = True
                # Retained observed counts may cover an exhausted trace tail,
                # but the missing ordered events still prohibit native PASS.
                for name in mismatches:
                    counts[key][name] = row[name]
            else:
                raise Refuted("retained entry observation contradicts replayed transitions")
    if set(entries) != {key for key in tickets if counts[key]["attempts"]}:
        incomplete = True
    completed = (len(grants) == 2 and cutoff and drained and successor_granted and stale_refused
                 and any(tickets[key]["selection"] == successor and counts[key]["entries"] == counts[key]["exits"] == 1 for key in tickets)
                 and active and not queue and not pending and not entered and set(tickets) == set(inventory))
    return {"grants": grants, "decisions": decisions, "counts": counts, "tickets": tickets, "entries": entries, "drains": drains,
            "census": census, "initial_authority": next((row["grant"]["authority"] for row in grants if row["grant"]["purpose"] == "initial"), None),
            "complete": bool(completed) and not incomplete}


def _observations(request: dict[str, Any]) -> dict[str, Any]:
    return {key: request[key] for key in ("capture_digest", "trace_digest", "terminal_census_digest",
                                         "execution_closure_digest", "revocation_cutoff")}


def _subject_binding(request: dict[str, Any]) -> dict[str, Any]:
    return {**{key: request[key] for key in ("subject_id", "object_digest", "collection_digest")},
            "initial_digest": _hash(canonical_bytes(request["initial"])),
            "successor_digest": _hash(canonical_bytes(request["successor"]))}


def _signed_preflight(value: dict[str, Any], request: dict[str, Any], policy: dict[str, Any]) -> tuple[list[tuple[str, str, bytes]], list[str], list[str]]:
    """Inspect independently usable signed bindings before unavailable peers."""
    signatures, failures, missing = [], [], []
    for kind, field in (("authority", "authority_admission"), ("observer", "observer_admission")):
        try:
            admission = value[field]
            if admission is None:
                missing.append("independently selected " + kind + " admission missing")
                continue
            if _hash(canonical_bytes(admission)) != policy[field + "_digest"]:
                raise Refuted("retained " + kind + " admission differs from external pin")
            expected = {"schema_version": ADMISSION_VERSION, "operation_id": request["operation_id"],
                        "boundary_id": request["boundary_id"], "execution_closure_digest": request["execution_closure_digest"],
                        "purpose": "grant-and-revoke" if kind == "authority" else "observe-complete-effect-census",
                        "keys": policy[kind + "_keys"], **_subject_binding(request)}
            signatures.append(_signed(admission, {policy["admission_key_id"]: policy["admission_public_key"]}, expected))
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            failures.append(str(exc))
        except (Unavailable, MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
            missing.append("independent admission checking unavailable")
    common = {"schema_version": AUTHORITY_VERSION, "operation_id": request["operation_id"],
              "boundary_id": request["boundary_id"], "capture_digest": request["capture_digest"],
              "execution_closure_digest": request["execution_closure_digest"], **_subject_binding(request)}
    attested = value["authority_attestations"]
    if type(attested) is not list or len(attested) > 64:
        failures.append("authority statement inventory differs")
    else:
        for statement in attested:
            try:
                row = _record(statement, {"schema_version", "key_id", "payload", "signature"}, "authority attestation")
                payload = _record(row["payload"], set(common) | {"kind", "record"}, "authority payload")
                if any(payload[key] != common[key] for key in common):
                    raise Refuted("authority statement contradicts selected operation")
                if payload["kind"] == "grant":
                    decision = _grant_decision(payload["record"])
                    grant = decision["grant"]
                    selected = request["initial"] if grant["purpose"] == "initial" else request["successor"]
                    if grant["selection"] != selected or grant["authority"] != row["key_id"]:
                        raise Refuted("signed grant differs from selected purpose or generation")
                elif payload["kind"] == "revocation":
                    record = _record(payload["record"], {"selection", "epoch", "revocation_view_digest", "revoked_authority"}, "revocation")
                    if (record["selection"] != request["initial"] or record["epoch"] != request["revocation_cutoff"]
                            or record["revocation_view_digest"] != request["revocation_view_digest"]
                            or record["revoked_authority"] != row["key_id"]):
                        raise Refuted("signed revocation contradicts selected cutoff or view")
                else:
                    raise Refuted("signed authority purpose differs")
                signatures.append(_signed(row, policy["authority_keys"], payload))
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                failures.append(str(exc))
            except (Unavailable, MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
                missing.append("independent authority checking unavailable")
    try:
        observer = value["observer_attestation"]
        if observer is None:
            missing.append("complete observer census missing")
        else:
            row = _record(observer, {"schema_version", "key_id", "payload", "signature"}, "observer attestation")
            fields = {"schema_version", "operation_id", "boundary_id", "capture_digest", "trace_digest",
                      "terminal_census_digest", "execution_closure_digest", "effect_inventory", "effect_census", "coverage_complete"}
            payload = _record(row["payload"], fields | set(_subject_binding(request)), "observer payload")
            fixed = {"schema_version": OBSERVER_VERSION, **_subject_binding(request), **{key: request[key] for key in (
                "operation_id", "boundary_id", "capture_digest", "trace_digest", "terminal_census_digest", "execution_closure_digest", "effect_inventory")}}
            if any(payload[key] != expected for key, expected in fixed.items()) or type(payload["coverage_complete"]) is not bool:
                raise Refuted("observer contradicts selected exact operation or inventory")
            census = payload["effect_census"]
            if type(census) is not list or len(census) > 4096:
                raise Refuted("observer effect census capacity differs")
            inventory = {effect["invocation_id"]: effect for effect in request["effect_inventory"]}
            names = []
            for item in census:
                item = _record(item, {"invocation_id", "effect_id", "effect_digest", "selection_digest", "attempts", "entries", "exits"}, "observer census row")
                name = _label(item["invocation_id"])
                if name not in inventory or any(item[key] != inventory[name][key] for key in inventory[name]):
                    raise Refuted("observer census substitutes selected effect identity")
                for key in ("attempts", "entries", "exits"):
                    _integer(item[key], 0, 4096)
                if not 0 <= item["exits"] <= item["entries"] <= item["attempts"] <= 1:
                    raise Refuted("observer census count ordering contradicts one-shot boundary")
                names.append(name)
            if names != sorted(set(names)) or payload["coverage_complete"] and set(names) != set(inventory):
                raise Refuted("asserted observer coverage omits or duplicates selected effects")
            signatures.append(_signed(row, policy["observer_keys"], payload))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        failures.append(str(exc))
    except (Unavailable, MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
        missing.append("independent observer checking unavailable")
    return signatures, failures, missing


def _signed_replay_preflight(value: dict[str, Any], request: dict[str, Any], replay: dict[str, Any]) -> None:
    """Known lifecycle/census contradictions precede unrelated byte outages."""
    for statement in value["authority_attestations"]:
        if type(statement) is not dict or type(statement.get("payload")) is not dict:
            continue
        payload = statement["payload"]
        if payload.get("kind") != "grant" or type(payload.get("record")) is not dict:
            continue
        supplied = _grant_decision(payload["record"])
        for decision in replay["grants"]:
            if (supplied["grant"]["purpose"] == decision["grant"]["purpose"]
                    and supplied["epoch"] == decision["epoch"] and supplied != decision):
                raise Refuted("signed grant contradicts exact committed decision")
    observer = value["observer_attestation"]
    if observer is None or type(observer) is not dict or type(observer.get("payload")) is not dict:
        return
    payload = observer["payload"]
    counts = {effect["invocation_id"]: {**effect, **replay["counts"].get(effect["invocation_id"], {
        "attempts": 0, "entries": 0, "exits": 0})} for effect in request["effect_inventory"]}
    census = payload.get("effect_census")
    if type(census) is not list:
        raise Refuted("signed observer census shape differs")
    for row in census:
        if type(row) is not dict or type(row.get("invocation_id")) is not str or counts.get(row["invocation_id"]) != row:
            raise Refuted("signed observer census contradicts known actual entries")
    if payload.get("coverage_complete") is True and set(replay["tickets"]) != set(counts):
        raise Refuted("asserted complete observer census omits registered effects")


def _evaluate(data: bytes | None, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    failures, missing, signatures = [], [], []
    observations = _observations(request)
    try:
        if policy["mechanism_digest"] != mechanism_digest():
            failures.append("selected installed mechanism differs")
    except (MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
        missing.append("installed source checking dependency unavailable")
    if request["successor"]["generation"] != request["initial"]["generation"] + 1 or request["successor"]["process_id"] != request["initial"]["process_id"]:
        return MechanismDecision(MechanismOutcome.FAIL, "selected successor contradicts generation or process")
    if data is None:
        return MechanismDecision(MechanismOutcome.FAIL if failures else MechanismOutcome.UNKNOWN,
                                 "; ".join(failures) if failures else "required retained evidence absent", observations)
    if len(data) > request["max_evidence_bytes"]:
        return MechanismDecision(MechanismOutcome.FAIL if failures else MechanismOutcome.UNKNOWN,
                                 "; ".join(failures) if failures else "selected evidence capacity exhausted", observations)
    replay = None
    try:
        value = _record(_json(data), {"schema_version", "capture_base64", "retained_payloads", "authority_admission",
                                    "observer_admission", "authority_attestations", "observer_attestation"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION:
            raise Refuted("retained evidence version differs")
        early_signatures, early_failures, early_missing = _signed_preflight(value, request, policy)
        signatures.extend(early_signatures)
        failures.extend(early_failures)
        missing.extend(early_missing)
        if value["capture_base64"] is None:
            missing.append("exact host capture missing")
        else:
            raw = _b64(value["capture_base64"], _MAX_EVIDENCE_BYTES)
            if _hash(raw) != request["capture_digest"]:
                raise Refuted("retained capture differs from selected bytes")
            capture = _record(_json(raw), {"schema_version", "initial", "intent", "result", "terminal_sequence",
                                         "trace_digest", "events", "observations"}, "capture")
            if capture["schema_version"] != "verifier-local-permission-slot-observation-1":
                raise Refuted("retained host capture version differs")
            # Inspect producer FAIL before every optional retained dependency.
            if type(capture["result"]) is dict and capture["result"].get("status") == "FAIL":
                raise Refuted("retained producer already reports a failure")
            try:
                replay = _replay(capture, request)
                _signed_replay_preflight(value, request, replay)
                if not replay["complete"]:
                    missing.append("selected lifecycle or actual stale attempt incomplete")
            except Unavailable as exc:
                missing.append(str(exc))
        payloads = value["retained_payloads"]
        if type(payloads) is not dict or len(payloads) > 8192:
            raise Refuted("retained payload map differs")
        retained = {}
        for ref, encoded in payloads.items():
            _digest(ref)
            raw = _b64(encoded, _MAX_EVIDENCE_BYTES)
            if _hash(raw) != ref:
                raise Refuted("retained payload commitment differs")
            retained[ref] = raw
        required = {request["execution_closure_digest"], request["revocation_view_digest"],
                    request["object_digest"], request["collection_digest"]}
        if replay is not None:
            for decision in replay["grants"]:
                required.update(decision["grant"][name] for name in ("permission_digest", "evidence_digest", "revocation_view_digest"))
        subject_raw = retained.get(request["object_digest"])
        if subject_raw is not None:
            subject = _record(_json(subject_raw), {"object_id", "kind", "payload", "operands"}, "subject")
            item = NamespaceObject.create(**subject)
            if (item.object_id != request["subject_id"] or item.kind.value != "VERIFIER"
                    or item.digest != request["object_digest"] or canonical_bytes(item.to_dict()) != subject_raw):
                raise Refuted("retained selected VERIFIER subject differs")
        for selected in (request["initial"], request["successor"]):
            required.update(selected[key] for key in ("artifact_digest", "instruction_digest", "policy_digest", "context_digest"))
            context_raw = retained.get(selected["context_digest"])
            if context_raw is None:
                missing.append("exact typed context bytes missing")
                continue
            context = context_binding(_json(context_raw))
            if canonical_bytes(context) != context_raw:
                raise Refuted("typed context bytes are noncanonical")
            required.update(context[key] for key in set(context) - {"schema_version"})
            for kind in ("TIME", "TOKEN", "ENV", "HARDWARE", "SPACE"):
                facet_raw = retained.get(context[kind])
                if facet_raw is None:
                    missing.append("exact typed context facet bytes missing")
                    continue
                facet = _record(_json(facet_raw), {"kind", "record"}, "context facet")
                if facet["kind"] != kind or canonical_bytes(facet) != facet_raw or type(facet["record"]) is not dict:
                    raise Refuted("typed context facet binding differs")
        required.update(row["effect_digest"] for row in request["effect_inventory"])
        if required - set(retained):
            missing.append("exact selected instruction, artifact, policy, context, effect or source bytes missing")
        closure_raw = retained.get(request["execution_closure_digest"])
        if closure_raw is not None:
            closure = _record(_json(closure_raw), {"schema_version", "executor_digest", "observer_digest", "harness_digest", "mechanism_digest"}, "execution closure")
            if closure["schema_version"] != EXECUTION_VERSION or canonical_bytes(closure) != closure_raw:
                raise Refuted("selected execution closure bytes differ")
            for name in set(closure) - {"schema_version"}:
                _digest(closure[name])
                if closure[name] not in retained:
                    missing.append("exact admitted execution source bytes missing")
            if closure["mechanism_digest"] != policy["mechanism_digest"]:
                raise Refuted("execution closure names another admitted native checker")
            manifest_raw = retained.get(closure["mechanism_digest"])
            if manifest_raw is not None:
                manifest = _record(_json(manifest_raw), set(_mechanism_paths()), "native source manifest")
                if canonical_bytes(manifest) != manifest_raw:
                    raise Refuted("retained native source manifest is noncanonical")
                for digest in manifest.values():
                    _hex(digest, 64)
                    if "sha256:" + digest not in retained:
                        missing.append("exact native checker dependency bytes missing")
        for kind, field in (("authority", "authority_admission"), ("observer", "observer_admission")):
            admission = value[field]
            if admission is None:
                missing.append("independently selected " + kind + " admission missing")
                continue
            if _hash(canonical_bytes(admission)) != policy[field + "_digest"]:
                raise Refuted("retained " + kind + " admission differs from external pin")
            expected = {
                "schema_version": ADMISSION_VERSION, "operation_id": request["operation_id"],
                "boundary_id": request["boundary_id"], "execution_closure_digest": request["execution_closure_digest"],
                "purpose": "grant-and-revoke" if kind == "authority" else "observe-complete-effect-census",
                "keys": policy[kind + "_keys"],
                **_subject_binding(request),
            }
            signatures.append(_signed(admission, {policy["admission_key_id"]: policy["admission_public_key"]}, expected))
        attested = value["authority_attestations"]
        if type(attested) is not list or len(attested) > 64:
            raise Refuted("authority statement inventory differs")
        common = {"schema_version": AUTHORITY_VERSION, "operation_id": request["operation_id"],
                  "boundary_id": request["boundary_id"], "capture_digest": request["capture_digest"],
                  "execution_closure_digest": request["execution_closure_digest"], **_subject_binding(request)}
        expected_statements = []
        if replay is not None:
            for decision in replay["grants"]:
                expected_statements.append(({**common, "kind": "grant", "record": decision}, decision["grant"]["authority"]))
            if replay["initial_authority"] is not None:
                expected_statements.append(({**common, "kind": "revocation", "record": {
                    "selection": request["initial"], "epoch": request["revocation_cutoff"],
                    "revocation_view_digest": request["revocation_view_digest"], "revoked_authority": replay["initial_authority"],
                }}, replay["initial_authority"]))
        used = set()
        for expected, key in expected_statements:
            candidates = [(number, row) for number, row in enumerate(attested)
                          if type(row) is dict and row.get("payload") == expected]
            if not candidates:
                missing.append("exact purpose-specific authority statement missing")
                continue
            if len(candidates) != 1 or key not in policy["authority_keys"]:
                raise Refuted("duplicate or unadmitted authority statement")
            number, row = candidates[0]
            used.add(number)
            signatures.append(_signed(row, {key: policy["authority_keys"][key]}, expected))
        # Every supplied statement must have an exact recognized target. A wrong
        # signature/intent cannot become UNKNOWN through a missing peer.
        for number in set(range(len(attested))) - used:
            row = _record(attested[number], {"schema_version", "key_id", "payload", "signature"}, "unmatched authority attestation")
            payload = _record(row["payload"], set(common) | {"kind", "record"}, "unmatched authority payload")
            if any(payload[key] != common[key] for key in common):
                raise Refuted("authority statement contradicts selected operation")
            if payload["kind"] == "grant":
                decision = _grant_decision(payload["record"])
                if (decision["grant"]["selection"] not in (request["initial"], request["successor"])
                        or decision["grant"]["authority"] != row["key_id"]):
                    raise Refuted("authority statement names another selected grant")
            elif payload["kind"] == "revocation":
                record = _record(payload["record"], {"selection", "epoch", "revocation_view_digest", "revoked_authority"}, "revocation")
                if (record["selection"] != request["initial"] or record["epoch"] != request["revocation_cutoff"]
                        or record["revocation_view_digest"] != request["revocation_view_digest"]
                        or record["revoked_authority"] != row["key_id"]):
                    raise Refuted("authority statement names another selected revocation")
            else:
                raise Refuted("authority statement purpose differs")
            signatures.append(_signed(row, policy["authority_keys"], payload))
            uncommitted = (payload["kind"] == "grant" and replay is not None
                           and payload["record"] in replay["decisions"] and payload["record"] not in replay["grants"])
            if replay is not None and replay["complete"] and not uncommitted:
                raise Refuted("authority statement contradicts selected complete lifecycle")
            missing.append("supplied authority statement lacks exact committed observation")
        observer = value["observer_attestation"]
        if observer is None or replay is None:
            missing.append("complete independently admitted observer census missing")
        else:
            row = _record(observer, {"schema_version", "key_id", "payload", "signature"}, "observer attestation")
            payload = _record(row["payload"], {"schema_version", "operation_id", "boundary_id", "capture_digest", "trace_digest",
                                              "terminal_census_digest", "execution_closure_digest", "effect_inventory", "effect_census", "coverage_complete"}
                                              | set(_subject_binding(request)), "observer payload")
            counts = [{**effect, **replay["counts"].get(effect["invocation_id"], {"attempts": 0, "entries": 0, "exits": 0})}
                      for effect in request["effect_inventory"]]
            if type(payload["coverage_complete"]) is not bool:
                raise Refuted("observer coverage flag differs")
            supplied_census = payload["effect_census"]
            if type(supplied_census) is not list or len(supplied_census) > 4096:
                raise Refuted("observer census capacity differs")
            if not payload["coverage_complete"]:
                known = {entry["invocation_id"]: entry for entry in counts}
                seen = set()
                for item in supplied_census:
                    item = _record(item, {"invocation_id", "effect_id", "effect_digest", "selection_digest", "attempts", "entries", "exits"}, "partial effect census")
                    key = _label(item["invocation_id"])
                    if key in seen or key not in known or item != known[key]:
                        raise Refuted("partial observer census contradicts known effect entry")
                    seen.add(key)
                counts = supplied_census
            expected = {"schema_version": OBSERVER_VERSION, **{key: request[key] for key in (
                "operation_id", "boundary_id", "capture_digest", "trace_digest", "terminal_census_digest", "execution_closure_digest", "effect_inventory")},
                "effect_census": counts, "coverage_complete": payload["coverage_complete"], **_subject_binding(request)}
            signatures.append(_signed(observer, policy["observer_keys"], expected))
            if not payload["coverage_complete"]:
                missing.append("observer coverage explicitly incomplete")
            if any(record["observer_id"] != row["key_id"] for record in replay["entries"].values()) or any(record["observer_id"] != row["key_id"] for record in replay["drains"]):
                raise Refuted("retained observations name another selected observer")
            if payload["coverage_complete"] and set(replay["tickets"]) != {effect["invocation_id"] for effect in request["effect_inventory"]}:
                raise Refuted("asserted complete effect census omits known registered effects")
    except Unavailable as exc:
        missing.append(str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        failures.append(str(exc) or "retained binding refuted")
    except (MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
        missing.append("retained checking dependency unavailable")
    if failures:
        return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(set(failures))), observations)
    # Check every independently usable signature before selected cancellation.
    for public, signature, message in signatures:
        try:
            _verify_signature(public, signature, message)
        except Refuted as exc:
            failures.append(str(exc))
        except (Unavailable, MemoryError, CancelledError, OSError, ImportError, RecursionError, OverflowError):
            missing.append("signature checking dependency unavailable")
        except Exception:
            # An unexpected later backend failure cannot erase an earlier refutation.
            missing.append("signature checking dependency unavailable")
    if failures:
        return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(set(failures))), observations)
    if request["cancelled"]:
        missing.append("explicitly selected checking cancellation")
    if missing:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "; ".join(sorted(set(missing))),
                                 {**observations, "checking_dependency": "REPLAY_UNAVAILABLE"})
    return MechanismDecision(MechanismOutcome.PASS, _PASS_DETAILS, observations)


def _selector_bytes(request: dict[str, Any]) -> bytes:
    return canonical_bytes({"schema_version": SELECTOR_VERSION, "independently_selected_request": request})


class _Mechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any], present: bool) -> None:
        self.request, self.policy, self.present = request, policy, present
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        parameters = {"request_digest": "sha256:" + canonical_digest(self.request),
                      "candidate_evidence_present": "true" if self.present else "false"}
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != parameters
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                or len(evidence) != 1 + int(self.present) or evidence[0] != _selector_bytes(self.request)):
            return MechanismDecision(MechanismOutcome.FAIL, "bound selected replacement differs")
        return _evaluate(evidence[1] if self.present else None, self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    present = request["evidence_ref"] in store
    selector = _selector_bytes(request)
    selector_ref = store.add(selector)
    if selector_ref == request["evidence_ref"]:
        raise VerifierReplacementError("selector and candidate identities must differ")
    refs = [selector_ref] + ([request["evidence_ref"]] if present else [])
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=tuple(refs), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(2, len(selector) + _MAX_EVIDENCE_BYTES),
        parameters={"request_digest": "sha256:" + canonical_digest(request),
                    "candidate_evidence_present": "true" if present else "false"},
    )
    session = VerificationSession(store)
    session.register(_Mechanism(request, policy, present))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
              "coordinate": COORDINATE, "object_kind": "VERIFIER", "scope": SCOPE,
              "complete_corrigibility_admission": "UNKNOWN",
              "finite_replacement": "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
              **{field: "NOT_ESTABLISHED" for field in _EXCLUDED}, "evaluation": evaluation.to_dict()}
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
                "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
                "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": refs,
                "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise VerifierReplacementError("certificate capacity exhausted")
    return encoded


def build_verifier_replacement_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *,
                                          policy: dict[str, Any]) -> bytes:
    admitted = _policy(policy)
    selected = _request(request, admitted)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _MAX_EVIDENCE_BYTES:
            raise VerifierReplacementError("immutable bounded candidate bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise VerifierReplacementError("candidate differs from selected evidence commitment")
    return _build(selected, admitted, store)


def recheck_verifier_replacement_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    admitted = _policy(policy)
    selected = _request(expected_request, admitted)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise VerifierReplacementError("immutable bounded certificate required")
    try:
        envelope = _record(_json(certificate_bytes), _ENVELOPE_FIELDS, "certificate")
        selector = _selector_bytes(selected)
        selector_ref = _hash(selector)
        payloads = envelope["evidence_payloads"]
        if type(payloads) is not dict:
            raise VerifierReplacementError("retained payload map differs")
        present = selected["evidence_ref"] in payloads
        refs = [selector_ref] + ([selected["evidence_ref"]] if present else [])
        if (envelope["schema_version"] != CERTIFICATE_VERSION
                or envelope["digest"] != "sha256:" + canonical_digest({key: value for key, value in envelope.items() if key != "digest"})
                or canonical_bytes(envelope["request"]) != canonical_bytes(selected)
                or envelope["policy_digest"] != selected["policy_digest"]
                or envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_refs"] != refs or set(payloads) != set(refs)):
            raise VerifierReplacementError("certificate differs from external selection")
        store = EvidenceStore()
        for ref in refs:
            raw = _b64(payloads[ref], len(selector) if ref == selector_ref else _MAX_EVIDENCE_BYTES)
            if store.add(raw) != ref:
                raise VerifierReplacementError("retained evidence commitment differs")
        if store.resolve(selector_ref) != selector:
            raise VerifierReplacementError("retained selector differs")
        rebuilt = _build(selected, admitted, store)
        current = strict_json_loads(rebuilt.decode("utf-8"))["result"]
        if rebuilt == certificate_bytes:
            return {**current, "replay_status": "REPRODUCED"}
        if current["status"] == "UNKNOWN" and current["evaluation"]["observations"].get("checking_dependency") == "REPLAY_UNAVAILABLE":
            carried = _record(envelope["result"], set(current), "carried result")
            if carried["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
                raise VerifierReplacementError("carried status differs")
            for key in set(current) - {"status", "evaluation", "finite_replacement"}:
                if carried[key] != current[key]:
                    raise VerifierReplacementError("carried claim boundary differs")
            if carried["finite_replacement"] != ("PASS" if carried["status"] == "PASS" else "NOT_ESTABLISHED"):
                raise VerifierReplacementError("carried finite predicate differs")
            carried_evaluation = _record(carried["evaluation"], set(current["evaluation"]), "carried evaluation")
            if (carried_evaluation["outcome"] != carried["status"]
                    or any(carried_evaluation[key] != current["evaluation"][key]
                           for key in set(carried_evaluation) - {"outcome", "details", "observations"})):
                raise VerifierReplacementError("carried evaluation binding differs")
            if carried["status"] == "PASS" and (carried_evaluation["details"] != _PASS_DETAILS
                    or carried_evaluation["observations"] != _observations(selected)):
                raise VerifierReplacementError("carried positive observations differ")
            # An unrepeatable negative result is never upgraded or erased.
            if carried["status"] == "FAIL":
                raise VerifierReplacementError("carried failure cannot be independently reproduced")
            return {**current, "replay_status": "UNAVAILABLE"}
        raise VerifierReplacementError("certificate result does not reproduce exactly")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, Unavailable) as exc:
        if isinstance(exc, VerifierReplacementError):
            raise
        raise VerifierReplacementError("replacement certificate cannot replay") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "REQUEST_VERSION", "POLICY_VERSION", "EVIDENCE_VERSION",
    "CERTIFICATE_VERSION", "CONTEXT_VERSION", "PROPOSITION_DIGEST", "MECHANISM_ID", "SCOPE",
    "VerifierReplacementDescriptor", "VerifierReplacementError", "registration", "mechanism_digest",
    "context_binding", "context_digest", "verifier_replacement_policy", "verifier_replacement_request",
    "verifier_replacement_signing_bytes", "build_verifier_replacement_certificate", "recheck_verifier_replacement_certificate",
]
