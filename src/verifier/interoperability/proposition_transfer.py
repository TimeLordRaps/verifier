"""Experimental Verifier Standard (VSTD) byte-grounded finite-set transfer.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8); identifier (ID). Set members are
dimensionless strings. This pure direct-module interface discharges no numbered
profile or VSTD-4 rung, authority grant, graph-wide deduction, or execution claim.
Receipts are deterministic semantic records, not authenticated execution logs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .network import NetworkError, SiloCommit, _path, canonical_bytes, digest_bytes


TRANSFER_SCHEMA = "VSTD-PROPOSITION-TRANSFER-0.1"
ASSESSMENT_SCHEMA = "VSTD-PROPOSITION-TRANSFER-ASSESSMENT-0.1"
RECEIPT_SCHEMA = "VSTD-PROPOSITION-TRANSFER-RECEIPT-0.1"
RULE_ID = "canonical_finite_set_union_v1"
PREDICATE_ID = "canonical_finite_set_subset_v1"
ARTIFACT_SCHEMA = "VSTD-CANONICAL-FINITE-SET-0.1"
MAX_RECORD_BYTES = 262144
MAX_EVIDENCE_BYTES = 4194304
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000
_STATUSES = {"PASS", "FAIL", "UNKNOWN", "INVALID"}
_PRECEDENCE = {"PASS": 0, "UNKNOWN": 1, "FAIL": 2, "INVALID": 3}
_REASONS = {
    "EVIDENCE_BINDING_FAIL", "EVIDENCE_BINDING_INVALID", "EVIDENCE_BINDING_UNKNOWN",
    "PREDICATE_FAIL", "PREDICATE_INVALID", "PREDICATE_UNKNOWN",
    "CONTEXT_PRESERVATION_FAIL", "CONTEXT_PRESERVATION_UNKNOWN",
    "ARTIFACT_RELATION_FAIL", "ARTIFACT_RELATION_INVALID", "ARTIFACT_RELATION_UNKNOWN",
    "UPPER_BOUND_PRESERVATION_FAIL", "UPPER_BOUND_PRESERVATION_INVALID",
    "UPPER_BOUND_PRESERVATION_UNKNOWN", "RESIDUAL_OBLIGATIONS", "UNSUPPORTED_RULE",
}


class PropositionTransferError(ValueError):
    """An experimental transfer wire record or receipt failed closed."""


def rule_profile_bytes() -> bytes:
    """Return the registered semantic rule identity, not executable code."""
    return canonical_bytes({
        "artifact_schema": ARTIFACT_SCHEMA, "context_policy": "EXACT", "facet": "items",
        "max_evidence_bytes": MAX_EVIDENCE_BYTES, "max_items": 256,
        "max_json_depth": MAX_JSON_DEPTH, "max_json_nodes": MAX_JSON_NODES,
        "max_objects": 34, "max_premises": 16, "max_record_bytes": MAX_RECORD_BYTES,
        "max_string_bytes": 256, "predicate_id": PREDICATE_ID, "rule_id": RULE_ID,
        "schema_version": "VSTD-PROPOSITION-TRANSFER-RULE-0.1",
    })


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise PropositionTransferError(f"{label} must have exactly its defined fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
        raise PropositionTransferError("text must be nonempty and at most 256 UTF-8 bytes")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise PropositionTransferError("digest must be an exact lowercase SHA-256 identity")
    return value


def _strings(value: Any) -> list[str]:
    if type(value) is not list or len(value) > 256:
        raise PropositionTransferError("string set must contain at most 256 entries")
    for item in value:
        _text(item)
    if value != sorted(set(value), key=lambda item: item.encode("utf-8")):
        raise PropositionTransferError("string set must be unique and in UTF-8 byte order")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PropositionTransferError("duplicate JSON object key")
        result[key] = value
    return result


def _decode(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or len(data) > MAX_RECORD_BYTES:
        raise PropositionTransferError("record must be immutable bytes within its byte bound")
    # Scan nesting before invoking the recursive JSON parser/canonical encoder.
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH + 1:
                raise PropositionTransferError("record exceeds JSON nesting bound")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, level = pending.pop()
            nodes += 1
            if level > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
                raise PropositionTransferError("record exceeds JSON depth or node bound")
            if type(item) is dict:
                pending.extend((child, level + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, level + 1) for child in item)
        if type(value) is not dict or canonical_bytes(value) != data:
            raise PropositionTransferError("record must be an exact canonical JSON object")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise PropositionTransferError(f"invalid bounded canonical record: {error}") from error


def _proposition(value: Any) -> dict[str, Any]:
    value = _object(value, {"commit_digest", "artifact_digest", "artifact_path", "size_bytes",
                            "predicate_id", "facet", "parameters", "context"}, "proposition")
    _digest(value["commit_digest"])
    _digest(value["artifact_digest"])
    try:
        _path(value["artifact_path"])
    except NetworkError as error:
        raise PropositionTransferError(str(error)) from error
    if type(value["size_bytes"]) is not int or not 0 <= value["size_bytes"] <= MAX_EVIDENCE_BYTES:
        raise PropositionTransferError("size_bytes must be a bounded nonnegative integer")
    _text(value["predicate_id"])
    _text(value["facet"])
    if type(value["parameters"]) is not dict:
        raise PropositionTransferError("parameters must be an opaque canonical JSON object")
    context = _object(value["context"], {"semantic_scope", "actor_scope", "agency_digest",
                                        "authority_model_digest", "assumptions", "exclusions"}, "context")
    _text(context["semantic_scope"])
    _text(context["actor_scope"])
    _digest(context["agency_digest"])
    if context["authority_model_digest"] is not None:
        _digest(context["authority_model_digest"])
    _strings(context["assumptions"])
    _strings(context["exclusions"])
    return value


def decode_transfer(data: bytes) -> dict[str, Any]:
    """Decode a strict bounded declaration; do not establish its propositions."""
    value = _object(_decode(data), {"schema_version", "rule_id", "rule_profile_digest",
                                    "premises", "conclusion", "residual_obligations"}, "transfer")
    if value["schema_version"] != TRANSFER_SCHEMA:
        raise PropositionTransferError("unsupported transfer schema_version")
    _text(value["rule_id"])
    _digest(value["rule_profile_digest"])
    premises = value["premises"]
    if type(premises) is not list or not 1 <= len(premises) <= 16:
        raise PropositionTransferError("transfer requires one to sixteen premises")
    for premise in premises:
        _proposition(premise)
    digests = [digest_bytes(canonical_bytes(premise)) for premise in premises]
    if digests != sorted(set(digests)):
        raise PropositionTransferError("premises must be unique in proposition-digest order")
    if len({(item["commit_digest"], item["artifact_path"]) for item in premises}) != len(premises):
        raise PropositionTransferError("repeated premise commit/path pair")
    _proposition(value["conclusion"])
    _strings(value["residual_obligations"])
    return value


def _combine(*states: str) -> str:
    return max(states, key=_PRECEDENCE.__getitem__)


def _retain(propositions: list[dict[str, Any]], evidence: Mapping[str, bytes]) -> dict[str, tuple[str, bytes | None]]:
    required = sorted({item[field] for item in propositions for field in ("commit_digest", "artifact_digest")})
    retained: dict[str, tuple[str, bytes | None]] = {}
    total = 0
    for digest in required:
        try:
            value = evidence[digest]
        except KeyError:
            retained[digest] = ("UNKNOWN", None)
            continue
        if not isinstance(value, (bytes, bytearray, memoryview)):
            retained[digest] = ("INVALID", None)
            continue
        try:
            # Inspect the intrinsic buffer, not caller-overridable size or
            # conversion methods on bytes/bytearray subclasses.
            with memoryview(value) as view:
                size = view.nbytes
                if size > MAX_RECORD_BYTES or total + size > MAX_EVIDENCE_BYTES:
                    retained[digest] = ("UNKNOWN", None)
                    continue
                copied = view.tobytes()
        except (TypeError, ValueError, BufferError):
            retained[digest] = ("INVALID", None)
            continue
        if len(copied) != size:
            retained[digest] = ("INVALID", None)
            continue
        total += len(copied)
        retained[digest] = ("PASS" if digest_bytes(copied) == digest else "INVALID", copied)
    return retained


def _commit_binding(proposition: dict[str, Any], state: str, data: bytes | None) -> str:
    if state != "PASS":
        return state
    try:
        commit = SiloCommit.from_dict(_decode(data))  # type: ignore[arg-type]
    except (ValueError, TypeError, KeyError, AttributeError):
        return "INVALID"
    census = {entry.path: entry.object_record for entry in commit.census}
    record = census.get(proposition["artifact_path"])
    context = proposition["context"]
    authority = None if commit.authority_model_path is None else census[commit.authority_model_path].object_digest
    return "PASS" if (
        record is not None and record.object_digest == proposition["artifact_digest"]
        and record.size_bytes == proposition["size_bytes"]
        and context["agency_digest"] == commit.authority_axiom_agency_digest
        and context["authority_model_digest"] == authority
    ) else "FAIL"


def _supported(proposition: dict[str, Any]) -> bool:
    return proposition["predicate_id"] == PREDICATE_ID and proposition["facet"] == "items"


def _sets(proposition: dict[str, Any], artifact_state: str, data: bytes | None) -> tuple[str, set[str], str, set[str]]:
    if not _supported(proposition):
        return "UNKNOWN", set(), "UNKNOWN", set()
    try:
        allowed = set(_strings(_object(proposition["parameters"], {"allowed_items"}, "parameters")["allowed_items"]))
        parameter_state = "PASS"
    except PropositionTransferError:
        allowed, parameter_state = set(), "INVALID"
    actual: set[str] = set()
    if artifact_state == "PASS":
        try:
            artifact = _object(_decode(data), {"schema_version", "items"}, "finite-set artifact")  # type: ignore[arg-type]
            if artifact["schema_version"] != ARTIFACT_SCHEMA:
                raise PropositionTransferError("unsupported finite-set artifact schema")
            actual = set(_strings(artifact["items"]))
        except PropositionTransferError:
            artifact_state = "INVALID"
    return parameter_state, allowed, artifact_state, actual


def assess_transfer(declaration_bytes: bytes, evidence: Mapping[str, bytes]) -> dict[str, Any]:
    """Recheck exact retained data with the registered finite-set rule only."""
    declaration = decode_transfer(declaration_bytes)
    propositions = [*declaration["premises"], declaration["conclusion"]]
    retained = _retain(propositions, evidence)
    results: list[dict[str, Any]] = []
    sets: list[tuple[str, set[str], str, set[str]]] = []
    for proposition in propositions:
        commit_state, commit_data = retained[proposition["commit_digest"]]
        binding = _commit_binding(proposition, commit_state, commit_data)
        artifact_state, artifact_data = retained[proposition["artifact_digest"]]
        if artifact_state == "PASS" and len(artifact_data) != proposition["size_bytes"]:  # type: ignore[arg-type]
            artifact_state = "INVALID"
        binding = _combine(binding, artifact_state)
        parameter_state, allowed, actual_state, actual = _sets(proposition, artifact_state, artifact_data)
        sets.append((parameter_state, allowed, actual_state, actual))
        predicate = _combine(parameter_state, actual_state)
        if predicate == "PASS":
            predicate = "PASS" if actual <= allowed else "FAIL"
        results.append({"proposition_digest": digest_bytes(canonical_bytes(proposition)),
                        "evidence_binding": binding, "predicate_result": predicate})
    supported_rule = declaration["rule_id"] == RULE_ID and declaration["rule_profile_digest"] == digest_bytes(rule_profile_bytes())
    context = relation = upper = "UNKNOWN"
    if supported_rule:
        if any(item["context"] != propositions[-1]["context"] for item in propositions[:-1]):
            context = "FAIL"
        elif all(_supported(item) for item in propositions):
            context = "PASS"
        relation = _combine(*(item[2] for item in sets))
        if relation == "PASS":
            relation = "PASS" if set().union(*(item[3] for item in sets[:-1])) == sets[-1][3] else "FAIL"
        upper = _combine(*(item[0] for item in sets))
        if upper == "PASS":
            upper = "PASS" if set().union(*(item[1] for item in sets[:-1])) <= sets[-1][1] else "FAIL"
    residual = "UNKNOWN" if declaration["residual_obligations"] else "PASS"
    reasons: set[str] = set()
    for result in results:
        for field, prefix in (("evidence_binding", "EVIDENCE_BINDING"), ("predicate_result", "PREDICATE")):
            if result[field] != "PASS":
                reasons.add(f"{prefix}_{result[field]}")
    for prefix, status in (("CONTEXT_PRESERVATION", context), ("ARTIFACT_RELATION", relation), ("UPPER_BOUND_PRESERVATION", upper)):
        if status != "PASS":
            reasons.add(f"{prefix}_{status}")
    if residual != "PASS":
        reasons.add("RESIDUAL_OBLIGATIONS")
    if not supported_rule:
        reasons.add("UNSUPPORTED_RULE")
    return {
        "schema_version": ASSESSMENT_SCHEMA, "premises": results[:-1], "conclusion": results[-1],
        "context_preservation": context, "artifact_relation": relation,
        "upper_bound_preservation": upper, "residual_closure": residual,
        "conclusion_support": "NOT_ESTABLISHED" if reasons else "SUPPORTED",
        "authority_admissibility": "NOT_ESTABLISHED", "reason_codes": sorted(reasons),
    }


def _assessment(value: Any) -> dict[str, Any]:
    value = _object(value, {"schema_version", "premises", "conclusion", "context_preservation",
                            "artifact_relation", "upper_bound_preservation", "residual_closure",
                            "conclusion_support", "authority_admissibility", "reason_codes"}, "assessment")
    if value["schema_version"] != ASSESSMENT_SCHEMA:
        raise PropositionTransferError("unsupported assessment schema_version")
    if type(value["premises"]) is not list or not 1 <= len(value["premises"]) <= 16:
        raise PropositionTransferError("assessment requires one to sixteen premises")
    for item in [*value["premises"], value["conclusion"]]:
        _object(item, {"proposition_digest", "evidence_binding", "predicate_result"}, "proposition result")
        _digest(item["proposition_digest"])
        if any(type(item[key]) is not str or item[key] not in _STATUSES for key in ("evidence_binding", "predicate_result")):
            raise PropositionTransferError("unsupported proposition result")
    for key in ("context_preservation", "artifact_relation", "upper_bound_preservation", "residual_closure"):
        if type(value[key]) is not str or value[key] not in _STATUSES:
            raise PropositionTransferError("unsupported transfer check status")
    if type(value["conclusion_support"]) is not str or value["conclusion_support"] not in {"SUPPORTED", "NOT_ESTABLISHED"} or value["authority_admissibility"] != "NOT_ESTABLISHED":
        raise PropositionTransferError("unsupported conclusion or authority status")
    if not set(_strings(value["reason_codes"])) <= _REASONS:
        raise PropositionTransferError("unsupported reason code")
    return value


def decode_transfer_receipt(data: bytes) -> dict[str, Any]:
    """Decode structure only; no claim of producer execution or recomputation."""
    value = _object(_decode(data), {"schema_version", "declaration_digest", "rule_profile_digest", "assessment"}, "receipt")
    if value["schema_version"] != RECEIPT_SCHEMA:
        raise PropositionTransferError("unsupported transfer receipt schema_version")
    _digest(value["declaration_digest"])
    _digest(value["rule_profile_digest"])
    _assessment(value["assessment"])
    return value


def build_transfer_receipt(declaration_bytes: bytes, evidence: Mapping[str, bytes]) -> bytes:
    """Build an unsigned deterministic semantic record from current evidence."""
    declaration = decode_transfer(declaration_bytes)
    return canonical_bytes({
        "schema_version": RECEIPT_SCHEMA, "declaration_digest": digest_bytes(declaration_bytes),
        "rule_profile_digest": declaration["rule_profile_digest"],
        "assessment": assess_transfer(declaration_bytes, evidence),
    })


def recheck_transfer_receipt(declaration_bytes: bytes, receipt_bytes: bytes, evidence: Mapping[str, bytes]) -> dict[str, Any]:
    """Require exact semantic-record equality after current evidence replay."""
    receipt = decode_transfer_receipt(receipt_bytes)
    declaration = decode_transfer(declaration_bytes)
    if receipt["declaration_digest"] != digest_bytes(declaration_bytes) or receipt["rule_profile_digest"] != declaration["rule_profile_digest"]:
        raise PropositionTransferError("TRANSFER_RECEIPT_BINDING_INVALID")
    rebuilt = build_transfer_receipt(declaration_bytes, evidence)
    if receipt_bytes != rebuilt:
        raise PropositionTransferError("TRANSFER_NOT_REPRODUCED")
    return decode_transfer_receipt(rebuilt)["assessment"]
