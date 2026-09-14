"""Experimental retained-silo formation inspection for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) admission precedes recursive decoding. This
local inspection is not a portable receipt or a silo assessment: exact census
retention, declared context binding, and fresh finite formation checking remain
separate. No source interpretation, ground origin, completeness, agency action
preservation, execution, or existing silo axis is established here.

Inputs are inert immutable bytes in a bounded built-in dictionary. Its retained
observations are not an atomic concurrent-storage snapshot. Limits count bytes
or dimensionless entries/containers; no filesystem or submitted code is used.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .formation_checker import check_formation
from .formation_wire import (
    CERTIFICATE_SCHEMA, SUBJECT_SCHEMA, FormationError, FormationLimitError,
    RESIDUAL_OBLIGATIONS, UnsupportedFormation, decode_certificate,
    decode_subject, profile_bytes, profile_digest,
)
from .network import (
    AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION, COMMIT_SCHEMA, MAX_ENTRIES, MAX_OBJECT_BYTES,
    NetworkError, SiloCommit, _digest, _path, authority_axiom_agency_digest,
    canonical_bytes, digest_bytes,
)

MAX_COMMIT_BYTES = 262144
MAX_COMMIT_JSON_DEPTH = 16
MAX_COMMIT_JSON_CONTAINERS = 8192
MAX_EVIDENCE_ENTRIES = MAX_ENTRIES
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
PROFILE_SCHEMA = "VSTD-TYPED-FORMATION-PROFILE-0.1"
_ROLES = {
    "subject": ("typed-formation-subject", SUBJECT_SCHEMA),
    "certificate": ("typed-formation-certificate", CERTIFICATE_SCHEMA),
    "profile": ("typed-formation-profile", PROFILE_SCHEMA),
}


def _decode_commit(data: bytes) -> SiloCommit:
    if type(data) is not bytes:
        raise FormationError("commit must be immutable bytes")
    if len(data) > MAX_COMMIT_BYTES:
        raise FormationLimitError("commit byte budget exceeded")
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
            if depth > MAX_COMMIT_JSON_DEPTH or containers > MAX_COMMIT_JSON_CONTAINERS:
                raise FormationLimitError("commit syntax budget exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise FormationError("unbalanced commit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise FormationError("duplicate commit field")
            value[key] = item
        return value

    value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    if canonical_bytes(value) != data:
        raise FormationError("commit must have canonical bytes")
    if type(value) is not dict or type(value.get("schema_version")) is not str:
        raise FormationError("commit schema discriminator required")
    if value["schema_version"] != COMMIT_SCHEMA:
        raise UnsupportedFormation("commit schema unsupported")
    return SiloCommit.from_dict(value)


def _snapshot(evidence: Mapping[str, bytes]) -> tuple[dict[str, Any], str | None]:
    # Refuse custom mapping callbacks and bound collection before retaining it.
    if type(evidence) is not dict:
        return {}, "EVIDENCE_MAPPING_UNSUPPORTED"
    if len(evidence) > MAX_EVIDENCE_ENTRIES:
        return {}, "EVIDENCE_ENTRY_LIMIT"
    retained: dict[str, Any] = {}
    try:
        for index, (key, value) in enumerate(evidence.items()):
            if index >= MAX_EVIDENCE_ENTRIES:
                return {}, "EVIDENCE_ENTRY_LIMIT"
            if type(key) is not str:
                return {}, "EVIDENCE_MAPPING_UNSUPPORTED"
            _digest(key)
            retained[key] = value if type(value) is bytes else None
    except NetworkError:
        return {}, "EVIDENCE_MAPPING_INVALID"
    except RuntimeError:
        return {}, "EVIDENCE_SNAPSHOT_UNAVAILABLE"
    return retained, None


def inspect_silo_formation(
    commit_bytes: bytes,
    evidence: Mapping[str, bytes],
    *,
    subject_path: str,
    certificate_path: str,
    profile_path: str,
    ground_path: str,
) -> dict[str, Any]:
    """Rehash the complete census and separately inspect one formation pair.

    BOUND means exact selected census bytes, role declarations, compiled profile,
    and declared context correspondence; it is not a formation verdict. COMPLETE
    means every census member's bytes and size were checked, not silo completeness.
    Agency MATCHED means only the exact canonical action-floor declaration and
    context equality, never action preservation.
    Known invalid observations dominate unavailable ones within each result surface.
    """

    reasons: set[str] = set()
    binding: set[str] = set()
    result: dict[str, Any] = {
        "commit_digest": None, "profile_digest": profile_digest(),
        "coordinates": {}, "coordinate_binding": "UNKNOWN",
        "snapshot_retention": "UNKNOWN", "agency_declaration": "UNKNOWN",
        "formation_report": None, "reason_codes": [],
        "residual_obligations": list(RESIDUAL_OBLIGATIONS),
    }

    def note(code: str, status: str | None = None) -> None:
        reasons.add(code)
        if status is not None:
            binding.add(status)

    try:
        commit = _decode_commit(commit_bytes)
    except (UnsupportedFormation, FormationLimitError):
        result["reason_codes"] = ["COMMIT_UNSUPPORTED_OR_LIMITED"]
        return result
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        result.update(coordinate_binding="INVALID", snapshot_retention="INVALID",
                      reason_codes=["COMMIT_INVALID"])
        return result
    result["commit_digest"] = digest_bytes(commit_bytes)
    entries = {entry.path: entry.object_record for entry in commit.census}
    paths = {"subject": subject_path, "certificate": certificate_path,
             "profile": profile_path, "ground": ground_path}
    selected = {}
    for role, path in paths.items():
        try:
            if type(path) is not str:
                raise NetworkError("path must be ordinary text")
            _path(path)
        except NetworkError:
            result["coordinates"][role] = {"path": None, "object_digest": None}
            note("SELECTED_PATH_INVALID", "INVALID")
            continue
        record = entries.get(path)
        result["coordinates"][role] = {
            "path": path, "object_digest": None if record is None else record.object_digest,
        }
        if record is None:
            note("SELECTED_PATH_NOT_IN_CENSUS", "INVALID")
        else:
            selected[role] = record
            if role in _ROLES:
                kind, schema = _ROLES[role]
                if (record.artifact_kind, record.declared_schema_id, record.media_type) != (
                    kind, schema, "application/json",
                ):
                    note("SELECTED_ROLE_DECLARATION_INVALID", "INVALID")
    if type(ground_path) is not str or ground_path not in commit.ground_paths:
        note("SELECTED_GROUND_NOT_DECLARED", "INVALID")

    retained, snapshot_error = _snapshot(evidence)
    states: dict[str, str] = {}
    payloads: dict[str, bytes] = {}
    used = 0
    required = sorted({record.object_digest for record in entries.values()})
    for digest in required:
        if snapshot_error:
            states[digest] = "UNKNOWN"
        elif digest not in retained:
            states[digest] = "MISSING"
        elif type(retained[digest]) is not bytes:
            states[digest] = "INVALID"
            note("OBJECT_BYTES_INVALID")
        else:
            payload = retained[digest]
            if len(payload) > MAX_OBJECT_BYTES or used + len(payload) > MAX_SNAPSHOT_BYTES:
                states[digest] = "UNKNOWN"
                note("SNAPSHOT_BYTE_LIMIT")
                continue
            used += len(payload)
            if digest_bytes(payload) != digest:
                states[digest] = "INVALID"
                note("OBJECT_DIGEST_MISMATCH")
            else:
                states[digest] = "RETAINED"
                payloads[digest] = payload
    census_states = set(states.values())
    if snapshot_error:
        note(snapshot_error)
        census_states.add("INVALID" if snapshot_error == "EVIDENCE_MAPPING_INVALID" else "UNKNOWN")
    for record in entries.values():
        payload = payloads.get(record.object_digest)
        if payload is not None and len(payload) != record.size_bytes:
            census_states.add("INVALID")
            note("OBJECT_SIZE_MISMATCH")
    if "MISSING" in census_states:
        note("CENSUS_OBJECT_MISSING")
    result["snapshot_retention"] = (
        "INVALID" if "INVALID" in census_states else
        "UNKNOWN" if "UNKNOWN" in census_states else
        "INCOMPLETE" if "MISSING" in census_states else "COMPLETE"
    )
    for record in selected.values():
        state = states[record.object_digest]
        if state == "INVALID":
            binding.add("INVALID")
        elif state != "RETAINED":
            note("SELECTED_OBJECT_UNAVAILABLE", "UNKNOWN")
        elif len(payloads[record.object_digest]) != record.size_bytes:
            binding.add("INVALID")

    role_bytes = {role: payloads.get(record.object_digest) for role, record in selected.items()}
    subject = certificate = None
    for role, decoder in (("subject", decode_subject), ("certificate", decode_certificate)):
        payload = role_bytes.get(role)
        if payload is None:
            continue
        try:
            decoded = decoder(payload)
            if role == "subject":
                subject = decoded
            else:
                certificate = decoded
        except (UnsupportedFormation, FormationLimitError):
            note("FORMATION_RECORD_UNSUPPORTED_OR_LIMITED", "UNKNOWN")
        except FormationError:
            note("FORMATION_RECORD_INVALID", "INVALID")
    if role_bytes.get("subject") is not None and role_bytes.get("certificate") is not None:
        result["formation_report"] = check_formation(role_bytes["subject"], role_bytes["certificate"])
    if commit.authority_axiom_agency_version != AUTHORITY_AXIOM_AGENCY_VERSION:
        note("AGENCY_DECLARATION_UNSUPPORTED", "UNKNOWN")
    elif authority_axiom_agency_digest(commit.authority_axiom_agency) != commit.authority_axiom_agency_digest:
        result["agency_declaration"] = "INVALID"
        note("AGENCY_DECLARATION_DIGEST_MISMATCH", "INVALID")
    elif commit.authority_axiom_agency != AUTHORITY_AXIOM_AGENCY:
        note("AGENCY_DECLARATION_UNSUPPORTED", "UNKNOWN")
    elif subject is not None:
        result["agency_declaration"] = "MATCHED"
    if subject is None:
        binding.add("UNKNOWN")
    else:
        context = subject["context"]
        if context["authority_axiom_agency_digest"] != commit.authority_axiom_agency_digest:
            result["agency_declaration"] = "INVALID"
            note("SUBJECT_AGENCY_CONTEXT_MISMATCH", "INVALID")
        if "ground" in selected and context["ground_artifact_digest"] != selected["ground"].object_digest:
            note("SUBJECT_GROUND_CONTEXT_MISMATCH", "INVALID")
        if "profile" in selected and subject["profile_digest"] != selected["profile"].object_digest:
            note("SUBJECT_PROFILE_COORDINATE_MISMATCH", "INVALID")
        if certificate is not None and (
            certificate["subject_digest"] != selected["subject"].object_digest
            or certificate["profile_digest"] != subject["profile_digest"]
            or certificate["root"] != subject["root"]
        ):
            note("CERTIFICATE_COORDINATE_MISMATCH", "INVALID")
    if role_bytes.get("profile") is not None and role_bytes["profile"] != profile_bytes():
        note("FORMATION_PROFILE_UNSUPPORTED", "UNKNOWN")
    result["coordinate_binding"] = (
        "INVALID" if "INVALID" in binding else "UNKNOWN" if "UNKNOWN" in binding else "BOUND"
    )
    result["reason_codes"] = sorted(reasons)
    return result
