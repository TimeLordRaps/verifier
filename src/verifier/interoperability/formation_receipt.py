"""Portable finite-formation semantic receipts for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) is bounded before recursive parsing. Secure
Hash Algorithm 256-bit (SHA-256) binds actual captured bytes, including negative
substitutions. Reproduction is not a passing verdict, execution provenance,
source self-derivation, completeness or authority axiom agency preservation.
This pure experimental interface neither retrieves artifacts nor executes code.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .formation_storage import _decode_commit, inspect_silo_formation
from .formation_wire import RESIDUAL_OBLIGATIONS, profile_digest
from .network import NetworkError, _digest, _path, canonical_bytes, digest_bytes

SELECTION_SCHEMA = "VSTD-SILO-FORMATION-SELECTION-0.1"
RECEIPT_SCHEMA = "VSTD-SILO-FORMATION-RECEIPT-0.1"
MAX_SELECTION_BYTES = 4096
MAX_RECEIPT_BYTES = 1048576
MAX_JSON_DEPTH = 16
MAX_JSON_CONTAINERS = 16384
MAX_COMMIT_BYTES = 262144
MAX_EVIDENCE_ENTRIES = 256
MAX_OBJECT_BYTES = 4194304
MAX_EVIDENCE_BYTES = 16777216
_PATHS = ("subject_path", "certificate_path", "profile_path", "ground_path")
_INVALID_REASONS = {
    "FORMATION_RECORD_INVALID", "FORMATION_CERTIFICATE_BINDING_INVALID",
    "FORMATION_CERTIFICATE_STEP_INVALID", "FORMATION_RULE_INVALID",
}
_UNKNOWN_REASONS = {"FORMATION_PROFILE_UNSUPPORTED", "FORMATION_LIMIT_EXCEEDED"}
_INSPECTION_REASONS = {
    "AGENCY_DECLARATION_DIGEST_MISMATCH", "AGENCY_DECLARATION_UNSUPPORTED",
    "CENSUS_OBJECT_MISSING", "CERTIFICATE_COORDINATE_MISMATCH", "COMMIT_INVALID",
    "COMMIT_UNSUPPORTED_OR_LIMITED", "EVIDENCE_ENTRY_LIMIT", "EVIDENCE_MAPPING_INVALID",
    "EVIDENCE_MAPPING_UNSUPPORTED", "EVIDENCE_SNAPSHOT_UNAVAILABLE",
    "FORMATION_PROFILE_UNSUPPORTED", "FORMATION_RECORD_INVALID",
    "FORMATION_RECORD_UNSUPPORTED_OR_LIMITED", "OBJECT_BYTES_INVALID",
    "OBJECT_DIGEST_MISMATCH", "OBJECT_SIZE_MISMATCH", "SELECTED_GROUND_NOT_DECLARED",
    "SELECTED_OBJECT_UNAVAILABLE", "SELECTED_PATH_INVALID", "SELECTED_PATH_NOT_IN_CENSUS",
    "SELECTED_ROLE_DECLARATION_INVALID", "SNAPSHOT_BYTE_LIMIT",
    "SUBJECT_AGENCY_CONTEXT_MISMATCH", "SUBJECT_GROUND_CONTEXT_MISMATCH",
    "SUBJECT_PROFILE_COORDINATE_MISMATCH",
}


class FormationReceiptError(ValueError):
    """A receipt admission or reproduction failed at the named boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str = "FORMATION_RECEIPT_INVALID") -> None:
    if not condition:
        raise FormationReceiptError(code)


def _limit(condition: bool) -> None:
    _require(condition, "FORMATION_RECEIPT_LIMIT_EXCEEDED")


def _fields(value: Any, names: set[str], code: str = "FORMATION_RECEIPT_INVALID") -> None:
    _require(type(value) is dict and set(value) == names, code)


def _coordinate(value: Any, code: str = "FORMATION_RECEIPT_INVALID") -> None:
    _require(type(value) is str, code)
    try:
        _digest(value)
    except NetworkError as exc:
        raise FormationReceiptError(code) from exc


def _portable_path(value: Any, code: str = "FORMATION_RECEIPT_INVALID") -> None:
    _require(type(value) is str, code)
    try:
        _path(value)
    except NetworkError as exc:
        raise FormationReceiptError(code) from exc


def _integer(value: Any, maximum: int, minimum: int = 0) -> None:
    _require(type(value) is int and minimum <= value <= maximum)


def _enum(value: Any, values: set[str]) -> None:
    _require(type(value) is str and value in values)


def _decode(data: bytes, maximum: int, code: str) -> dict[str, Any]:
    _require(type(data) is bytes, code)
    _limit(len(data) <= maximum)
    depth = containers = 0
    quoted = escaped = False
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
            containers += 1
            _limit(depth <= MAX_JSON_DEPTH and containers <= MAX_JSON_CONTAINERS)
        elif byte in (93, 125):
            depth -= 1
            _require(depth >= 0, code)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            _require(key not in value, code)
            value[key] = item
        return value

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
        _require(canonical_bytes(value) == data, code)
    except FormationReceiptError:
        raise
    except (ValueError, TypeError, UnicodeError, NetworkError) as exc:
        raise FormationReceiptError(code) from exc
    _require(type(value) is dict, code)
    return value


def _selection(value: Any, code: str) -> dict[str, Any]:
    _fields(value, {"schema_version", "commit_digest", *_PATHS}, code)
    _require(value["schema_version"] == SELECTION_SCHEMA, code)
    _coordinate(value["commit_digest"], code)
    for key in _PATHS:
        _portable_path(value[key], code)
    return value


def decode_formation_selection(selection_bytes: bytes) -> dict[str, Any]:
    """Admit a portable selection, not its existence, roles or authority."""
    code = "FORMATION_SELECTION_INVALID"
    return _selection(_decode(selection_bytes, MAX_SELECTION_BYTES, code), code)


def _residuals(value: Any) -> None:
    _require(type(value) is list and value == list(RESIDUAL_OBLIGATIONS))


def _reasons(value: Any, vocabulary: set[str]) -> None:
    _require(type(value) is list and len(value) <= len(vocabulary))
    for item in value:
        _enum(item, vocabulary)
    _require(value == sorted(set(value)))


def _indices(value: Any, *, nonempty: bool = False) -> None:
    _require(type(value) is list and int(nonempty) <= len(value) <= 1024)
    for index in value:
        _integer(index, 1023)
    _require(value == sorted(set(value)))


def _observation(value: Any) -> None:
    _fields(value, {"type", "denotation_digest", "source_digest", "target_digest", "path_steps",
                    "quote_rank", "required_depth", "formation_digest", "dependency_nodes", "quote_origins"})
    kind = value["type"]
    _require(type(kind) is str)
    wrappers = 0
    while kind.startswith("CODE(") and kind.endswith(")"):
        wrappers += 1
        _require(wrappers <= 64)
        kind = kind[5:-1]
    _enum(kind, {"FORM", "PATH"})
    for key in ("denotation_digest", "formation_digest"):
        _coordinate(value[key])
    steps = value["path_steps"]
    _require(type(steps) is list and len(steps) <= 4096)
    if value["type"] == "PATH":
        _coordinate(value["source_digest"])
        _coordinate(value["target_digest"])
        for step in steps:
            _fields(step, {"source_digest", "target_digest"})
            _coordinate(step["source_digest"])
            _coordinate(step["target_digest"])
    else:
        _require(value["source_digest"] is None and value["target_digest"] is None and not steps)
    _integer(value["quote_rank"], 64)
    _integer(value["required_depth"], 64, 1)
    _indices(value["dependency_nodes"], nonempty=True)
    _indices(value["quote_origins"])


def _formation_report(value: Any) -> None:
    _fields(value, {"status", "subject_digest", "profile_digest", "root", "observation",
                    "reason_codes", "residual_obligations"})
    _enum(value["status"], {"CHECKED", "INVALID", "UNKNOWN"})
    _coordinate(value["profile_digest"])
    if value["subject_digest"] is None:
        _require(value["root"] is None)
    else:
        _coordinate(value["subject_digest"])
        _integer(value["root"], 1023)
    _residuals(value["residual_obligations"])
    if value["status"] == "CHECKED":
        _require(value["subject_digest"] is not None and value["reason_codes"] == [])
        _observation(value["observation"])
    else:
        _require(value["observation"] is None)
        _reasons(value["reason_codes"], _INVALID_REASONS if value["status"] == "INVALID" else _UNKNOWN_REASONS)
        _require(len(value["reason_codes"]) == 1)


def _inspection(value: Any) -> None:
    _fields(value, {"commit_digest", "profile_digest", "coordinates", "coordinate_binding",
                    "snapshot_retention", "agency_declaration", "formation_report",
                    "reason_codes", "residual_obligations"})
    _coordinate(value["profile_digest"])
    coordinates = value["coordinates"]
    if value["commit_digest"] is None:
        _fields(coordinates, set())
        _require(value["formation_report"] is None)
    else:
        _coordinate(value["commit_digest"])
        _fields(coordinates, {"subject", "certificate", "profile", "ground"})
        for coordinate in coordinates.values():
            _fields(coordinate, {"path", "object_digest"})
            if coordinate["path"] is not None:
                _portable_path(coordinate["path"])
            if coordinate["object_digest"] is not None:
                _coordinate(coordinate["object_digest"])
    _enum(value["coordinate_binding"], {"BOUND", "INVALID", "UNKNOWN"})
    _enum(value["snapshot_retention"], {"COMPLETE", "INCOMPLETE", "INVALID", "UNKNOWN"})
    _enum(value["agency_declaration"], {"MATCHED", "INVALID", "UNKNOWN"})
    _reasons(value["reason_codes"], _INSPECTION_REASONS)
    _residuals(value["residual_obligations"])
    if value["formation_report"] is not None:
        _formation_report(value["formation_report"])


def decode_formation_receipt(receipt_bytes: bytes) -> dict[str, Any]:
    """Check exact carried grammar only; recomputation remains a separate gate."""
    value = _decode(receipt_bytes, MAX_RECEIPT_BYTES, "FORMATION_RECEIPT_INVALID")
    _fields(value, {"schema_version", "selection", "selection_digest", "rule_profile_digest",
                    "observed_evidence", "inspection"})
    _require(value["schema_version"] == RECEIPT_SCHEMA)
    _selection(value["selection"], "FORMATION_RECEIPT_INVALID")
    _coordinate(value["selection_digest"])
    _coordinate(value["rule_profile_digest"])
    observations = value["observed_evidence"]
    _require(type(observations) is list)
    _limit(len(observations) <= MAX_EVIDENCE_ENTRIES)
    requested: list[str] = []
    total = 0
    for observation in observations:
        _fields(observation, {"requested_digest", "observed_digest", "size_bytes"})
        _coordinate(observation["requested_digest"])
        _coordinate(observation["observed_digest"])
        _integer(observation["size_bytes"], 2**53 - 1)
        _limit(observation["size_bytes"] <= MAX_OBJECT_BYTES)
        total += observation["size_bytes"]
        _limit(total <= MAX_EVIDENCE_BYTES)
        requested.append(observation["requested_digest"])
    _require(requested == sorted(set(requested)))
    _inspection(value["inspection"])
    return value


def _capture(evidence: Mapping[str, bytes]) -> dict[str, bytes]:
    code = "FORMATION_RECEIPT_INPUT_INVALID"
    _require(type(evidence) is dict, code)
    _limit(len(evidence) <= MAX_EVIDENCE_ENTRIES)
    captured: dict[str, bytes] = {}
    total = 0
    try:
        for index, (key, payload) in enumerate(evidence.items()):
            _limit(index < MAX_EVIDENCE_ENTRIES)
            _coordinate(key, code)
            _require(type(payload) is bytes, code)
            _limit(len(payload) <= MAX_OBJECT_BYTES)
            total += len(payload)
            _limit(total <= MAX_EVIDENCE_BYTES)
            captured[key] = payload
    except RuntimeError as exc:
        raise FormationReceiptError(code) from exc
    return captured


def build_formation_receipt(
    selection_bytes: bytes, commit_bytes: bytes, evidence: Mapping[str, bytes],
) -> bytes:
    """Capture portable inputs, then freshly inspect their exact selected bytes."""
    selection = decode_formation_selection(selection_bytes)
    _require(type(commit_bytes) is bytes, "FORMATION_RECEIPT_INPUT_INVALID")
    _limit(len(commit_bytes) <= MAX_COMMIT_BYTES)
    _require(digest_bytes(commit_bytes) == selection["commit_digest"], "FORMATION_RECEIPT_BINDING_INVALID")
    captured = _capture(evidence)
    try:
        commit = _decode_commit(commit_bytes)
        required = sorted({entry.object_record.object_digest for entry in commit.census})
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        required = []
    selected = {digest: captured[digest] for digest in required if digest in captured}
    observations = [{"requested_digest": digest, "observed_digest": digest_bytes(payload),
                     "size_bytes": len(payload)} for digest, payload in selected.items()]
    inspection = inspect_silo_formation(commit_bytes, selected, **{key: selection[key] for key in _PATHS})
    receipt = canonical_bytes({
        "schema_version": RECEIPT_SCHEMA, "selection": selection,
        "selection_digest": digest_bytes(selection_bytes), "rule_profile_digest": profile_digest(),
        "observed_evidence": observations, "inspection": inspection,
    })
    decode_formation_receipt(receipt)
    return receipt


def recheck_formation_receipt(
    selection_bytes: bytes, commit_bytes: bytes, receipt_bytes: bytes, evidence: Mapping[str, bytes],
) -> dict[str, Any]:
    """Return the fresh inspection only when the entire receipt is reproduced."""
    receipt = decode_formation_receipt(receipt_bytes)
    selection = decode_formation_selection(selection_bytes)
    _require(receipt["selection"] == selection
             and receipt["selection_digest"] == digest_bytes(selection_bytes)
             and receipt["rule_profile_digest"] == profile_digest(), "FORMATION_RECEIPT_BINDING_INVALID")
    rebuilt = build_formation_receipt(selection_bytes, commit_bytes, evidence)
    _require(rebuilt == receipt_bytes, "FORMATION_RECEIPT_NOT_REPRODUCED")
    return decode_formation_receipt(rebuilt)["inspection"]
