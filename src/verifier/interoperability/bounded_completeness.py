"""Experimental bounded completeness for Verifier Standard (VSTD) evidence.

JavaScript Object Notation (JSON) records, Secure Hash Algorithm 256-bit
(SHA-256) identities, and identifier (ID) labels are dimensionless.  This
direct-module sidecar establishes
only disposition completeness relative to one exact, externally source-grounded
finite denominator.  It does not establish an absolute universe, logical
decidability, semantic truth, producer independence, or completeness outside the
declared profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping

from .source_grounding import (
    GroundingResult,
    decode_source_grounding_declaration,
    recheck_source_grounding_receipt,
)


DECLARATION_SCHEMA = "VSTD-BOUNDED-COMPLETENESS-0.1"
DENOMINATOR_SCHEMA = "VSTD-BOUNDED-COMPLETENESS-DENOMINATOR-0.1"
OBSERVATIONS_SCHEMA = "VSTD-BOUNDED-COMPLETENESS-OBSERVATIONS-0.1"
RECEIPT_SCHEMA = "VSTD-BOUNDED-COMPLETENESS-RECEIPT-0.1"
MECHANISM_PROFILE_SCHEMA = "VSTD-BOUNDED-COMPLETENESS-MECHANISM-PROFILE-0.1"
PROFILE_ID = "source-grounded-finite-disposition-coverage-v1"
CHECKER_IMPLEMENTATION = "verifier.interoperability.bounded_completeness"
CHECKER_VERSION = "0.1"
MAX_RECORD_BYTES = 262_144
MAX_OBJECT_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 8_388_608
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 16_384
MAX_TEXT_BYTES = 512
MAX_MEMBERS = 256
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESIDUALS = (
    "ABSOLUTE_UNIVERSE_NOT_ESTABLISHED",
    "DENOMINATOR_AUTHORITY_NOT_ESTABLISHED",
    "GENERAL_LOGICAL_DECIDABILITY_NOT_ESTABLISHED",
    "GENERAL_SEMANTIC_COMPLETENESS_NOT_ESTABLISHED",
    "PRODUCER_INDEPENDENCE_NOT_ESTABLISHED",
)


class BoundedCompletenessError(ValueError):
    """A bounded-completeness record failed strict decoding or recheck."""


class CompletenessResult(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class ExactBytesReference:
    digest: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class GroundingReference:
    declaration_digest: str
    receipt_digest: str
    ground_proposition_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_digest": self.declaration_digest,
            "ground_proposition_digest": self.ground_proposition_digest,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class BoundedCompletenessDeclaration:
    profile_id: str
    denominator: ExactBytesReference
    denominator_grounding: GroundingReference
    observations: ExactBytesReference
    declarer_coordinate: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "declarer_coordinate": self.declarer_coordinate,
            "denominator": self.denominator.to_dict(),
            "denominator_grounding": self.denominator_grounding.to_dict(),
            "observations": self.observations.to_dict(),
            "profile_id": self.profile_id,
            "schema_version": DECLARATION_SCHEMA,
        }


@dataclass(frozen=True)
class MemberAssessment:
    member_id: str
    ground_proposition_digest: str
    grounding_result: str
    disposition: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "ground_proposition_digest": self.ground_proposition_digest,
            "grounding_result": self.grounding_result,
            "member_id": self.member_id,
        }


@dataclass(frozen=True)
class CheckerCoordinate:
    implementation_id: str
    implementation_version: str
    mechanism_profile_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "implementation_id": self.implementation_id,
            "implementation_version": self.implementation_version,
            "mechanism_profile_digest": self.mechanism_profile_digest,
        }


@dataclass(frozen=True)
class BoundedCompletenessReceipt:
    declaration_digest: str
    denominator_digest: str
    observations_digest: str
    profile_id: str
    checker_coordinate: CheckerCoordinate
    result: CompletenessResult
    checks: tuple[tuple[str, str], ...]
    member_assessments: tuple[MemberAssessment, ...]
    effectiveness: tuple[tuple[str, int | str], ...]
    reason_codes: tuple[str, ...]
    residual_obligations: tuple[str, ...] = _RESIDUALS

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker_coordinate": self.checker_coordinate.to_dict(),
            "checks": dict(self.checks),
            "declaration_digest": self.declaration_digest,
            "denominator_digest": self.denominator_digest,
            "effectiveness": dict(self.effectiveness),
            "member_assessments": [item.to_dict() for item in self.member_assessments],
            "observations_digest": self.observations_digest,
            "profile_id": self.profile_id,
            "reason_codes": list(self.reason_codes),
            "residual_obligations": list(self.residual_obligations),
            "result": self.result.value,
            "schema_version": RECEIPT_SCHEMA,
        }


def canonical_bytes(value: Any) -> bytes:
    """Encode an exact JSON value for deterministic byte identity."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 byte identity."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def mechanism_profile_bytes() -> bytes:
    """Return the bounded mechanism profile, not an absolute-completeness claim."""

    return canonical_bytes(
        {
            "decisive_grounding_results": ["ESTABLISHED", "REFUTED"],
            "denominator_kind": "EXACT_EXTERNALLY_SOURCE_GROUNDED_FINITE_SET",
            "max_evidence_bytes": MAX_EVIDENCE_BYTES,
            "max_json_depth": MAX_JSON_DEPTH,
            "max_json_nodes": MAX_JSON_NODES,
            "max_members": MAX_MEMBERS,
            "max_object_bytes": MAX_OBJECT_BYTES,
            "max_record_bytes": MAX_RECORD_BYTES,
            "profile_id": PROFILE_ID,
            "schema_version": MECHANISM_PROFILE_SCHEMA,
        }
    )


def mechanism_profile_digest() -> str:
    return digest_bytes(mechanism_profile_bytes())


def current_checker_coordinate() -> CheckerCoordinate:
    return CheckerCoordinate(
        CHECKER_IMPLEMENTATION, CHECKER_VERSION, mechanism_profile_digest()
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BoundedCompletenessError("duplicate JSON object key")
        value[key] = item
    return value


def _decode(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or not data or len(data) > MAX_RECORD_BYTES:
        raise BoundedCompletenessError("record must be nonempty immutable bytes within its bound")
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
                raise BoundedCompletenessError("record exceeds JSON nesting bound")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise BoundedCompletenessError("record has unbalanced JSON nesting")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, level = pending.pop()
            nodes += 1
            if level > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
                raise BoundedCompletenessError("record exceeds JSON depth or node bound")
            if type(item) is dict:
                pending.extend((child, level + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, level + 1) for child in item)
        if type(value) is not dict or canonical_bytes(value) != data:
            raise BoundedCompletenessError("record must be one exact canonical JSON object")
    except BoundedCompletenessError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise BoundedCompletenessError("invalid bounded JSON record") from error
    return value


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise BoundedCompletenessError(f"{label} must have exactly its defined fields")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise BoundedCompletenessError(f"{label} must be nonempty bounded text")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise BoundedCompletenessError(f"{label} must be an exact lowercase SHA-256 identity")
    return value


def _reference(value: Any, label: str) -> ExactBytesReference:
    value = _object(value, {"digest", "size_bytes"}, label)
    digest = _digest(value["digest"], f"{label}.digest")
    size = value["size_bytes"]
    if type(size) is not int or not 0 <= size <= MAX_RECORD_BYTES:
        raise BoundedCompletenessError(f"{label}.size_bytes exceeds the record bound")
    return ExactBytesReference(digest, size)


def _grounding_reference(value: Any, label: str) -> GroundingReference:
    value = _object(
        value,
        {"declaration_digest", "ground_proposition_digest", "receipt_digest"},
        label,
    )
    return GroundingReference(
        _digest(value["declaration_digest"], f"{label}.declaration_digest"),
        _digest(value["receipt_digest"], f"{label}.receipt_digest"),
        _digest(value["ground_proposition_digest"], f"{label}.ground_proposition_digest"),
    )


def decode_bounded_completeness_declaration(
    data: bytes,
) -> BoundedCompletenessDeclaration:
    value = _object(
        _decode(data),
        {
            "declarer_coordinate",
            "denominator",
            "denominator_grounding",
            "observations",
            "profile_id",
            "schema_version",
        },
        "bounded completeness declaration",
    )
    if value["schema_version"] != DECLARATION_SCHEMA:
        raise BoundedCompletenessError("unsupported declaration schema_version")
    return BoundedCompletenessDeclaration(
        profile_id=_text(value["profile_id"], "profile_id"),
        denominator=_reference(value["denominator"], "denominator"),
        denominator_grounding=_grounding_reference(
            value["denominator_grounding"], "denominator_grounding"
        ),
        observations=_reference(value["observations"], "observations"),
        declarer_coordinate=_text(value["declarer_coordinate"], "declarer_coordinate"),
    )


def _denominator(data: bytes) -> tuple[str, str, list[dict[str, str]]]:
    value = _object(
        _decode(data), {"members", "profile_id", "schema_version", "subject_id"}, "denominator"
    )
    if value["schema_version"] != DENOMINATOR_SCHEMA:
        raise BoundedCompletenessError("unsupported denominator schema_version")
    profile = _text(value["profile_id"], "denominator.profile_id")
    subject_id = _text(value["subject_id"], "denominator.subject_id")
    members = value["members"]
    if type(members) is not list or not 1 <= len(members) <= MAX_MEMBERS:
        raise BoundedCompletenessError("denominator requires one to 256 members")
    parsed = []
    for item in members:
        item = _object(
            item, {"ground_proposition_digest", "grounding_declaration_digest", "member_id"}, "member"
        )
        parsed.append(
            {
                "ground_proposition_digest": _digest(
                    item["ground_proposition_digest"], "member.ground_proposition_digest"
                ),
                "grounding_declaration_digest": _digest(
                    item["grounding_declaration_digest"], "member.grounding_declaration_digest"
                ),
                "member_id": _text(item["member_id"], "member.member_id"),
            }
        )
    if parsed != sorted(parsed, key=lambda item: item["member_id"].encode("utf-8")):
        raise BoundedCompletenessError("denominator members must be in member identifier byte order")
    if len({item["member_id"] for item in parsed}) != len(parsed):
        raise BoundedCompletenessError("denominator member identifiers must be unique")
    if len({item["ground_proposition_digest"] for item in parsed}) != len(parsed):
        raise BoundedCompletenessError("denominator propositions must be unique")
    return profile, subject_id, parsed


def _denominator_census_digest(
    subject_id: str, members: list[dict[str, str]]
) -> str:
    return digest_bytes(
        canonical_bytes({"members": members, "subject_id": subject_id})
    )


def _observations(data: bytes) -> tuple[str, str, list[dict[str, str]]]:
    value = _object(
        _decode(data),
        {"denominator_digest", "members", "procedure_id", "profile_id", "schema_version"},
        "observations",
    )
    if value["schema_version"] != OBSERVATIONS_SCHEMA:
        raise BoundedCompletenessError("unsupported observations schema_version")
    profile = _text(value["profile_id"], "observations.profile_id")
    denominator_digest = _digest(value["denominator_digest"], "observations.denominator_digest")
    if value["procedure_id"] != "source-grounding-replay-v1":
        raise BoundedCompletenessError("unsupported observation procedure_id")
    members = value["members"]
    if type(members) is not list or len(members) > MAX_MEMBERS:
        raise BoundedCompletenessError("observations contain too many members")
    parsed = []
    for item in members:
        item = _object(
            item, {"grounding_declaration_digest", "grounding_receipt_digest", "member_id"}, "observation"
        )
        parsed.append(
            {
                "grounding_declaration_digest": _digest(
                    item["grounding_declaration_digest"], "observation.grounding_declaration_digest"
                ),
                "grounding_receipt_digest": _digest(
                    item["grounding_receipt_digest"], "observation.grounding_receipt_digest"
                ),
                "member_id": _text(item["member_id"], "observation.member_id"),
            }
        )
    if parsed != sorted(parsed, key=lambda item: item["member_id"].encode("utf-8")):
        raise BoundedCompletenessError("observations must be in member identifier byte order")
    if len({item["member_id"] for item in parsed}) != len(parsed):
        raise BoundedCompletenessError("observation member identifiers must be unique")
    return profile, denominator_digest, parsed


def _copy_evidence(value: Any) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        with memoryview(value) as view:
            if view.nbytes > MAX_OBJECT_BYTES:
                return None
            copied = view.tobytes()
    except (TypeError, ValueError, BufferError):
        return None
    return copied


@dataclass
class _EvidenceBudget:
    retained_digests: set[str]
    retained_bytes: int = 0


def _lookup(
    digest: str, evidence: Mapping[str, bytes], budget: _EvidenceBudget
) -> tuple[str, bytes | None]:
    try:
        supplied = evidence[digest]
    except KeyError:
        return "MISSING", None
    copied = _copy_evidence(supplied)
    if copied is None or digest_bytes(copied) != digest:
        return "INVALID", None
    if digest not in budget.retained_digests:
        if budget.retained_bytes + len(copied) > MAX_EVIDENCE_BYTES:
            return "LIMIT", None
        budget.retained_digests.add(digest)
        budget.retained_bytes += len(copied)
    return "BOUND", copied


def _ground_proposition_digest(declaration_bytes: bytes) -> str:
    declaration = decode_source_grounding_declaration(declaration_bytes)
    return digest_bytes(canonical_bytes(declaration.ground_proposition.to_dict()))


def _grounding_result(
    reference: GroundingReference,
    expected_source_digest: str | None,
    evidence: Mapping[str, bytes],
    budget: _EvidenceBudget,
) -> tuple[str, str]:
    declaration_state, declaration_bytes = _lookup(
        reference.declaration_digest, evidence, budget
    )
    receipt_state, receipt_bytes = _lookup(reference.receipt_digest, evidence, budget)
    if "INVALID" in {declaration_state, receipt_state}:
        return "INVALID", "GROUNDING_BYTES_INVALID"
    if "LIMIT" in {declaration_state, receipt_state}:
        return "UNKNOWN", "EVIDENCE_BUDGET_EXHAUSTED"
    if "MISSING" in {declaration_state, receipt_state}:
        return "UNKNOWN", "GROUNDING_BYTES_MISSING"
    assert declaration_bytes is not None and receipt_bytes is not None
    try:
        declaration = decode_source_grounding_declaration(declaration_bytes)
        if _ground_proposition_digest(declaration_bytes) != reference.ground_proposition_digest:
            return "INVALID", "GROUND_PROPOSITION_BINDING_INVALID"
        if expected_source_digest is not None and declaration.source.digest != expected_source_digest:
            return "INVALID", "GROUND_SOURCE_BINDING_INVALID"
        source_state, _source_bytes = _lookup(declaration.source.digest, evidence, budget)
        certificate_state, _certificate_bytes = _lookup(
            declaration.certificate.digest, evidence, budget
        )
        if "INVALID" in {source_state, certificate_state}:
            return "INVALID", "GROUNDING_DEPENDENCY_INVALID"
        if "LIMIT" in {source_state, certificate_state}:
            return "UNKNOWN", "EVIDENCE_BUDGET_EXHAUSTED"
        if "MISSING" in {source_state, certificate_state}:
            return "UNKNOWN", "GROUNDING_DEPENDENCY_MISSING"
        receipt = recheck_source_grounding_receipt(
            declaration_bytes, receipt_bytes, evidence
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return "INVALID", "GROUNDING_RECHECK_INVALID"
    if receipt.result is GroundingResult.ESTABLISHED:
        return "ESTABLISHED", "GROUNDING_ESTABLISHED"
    if receipt.result is GroundingResult.REFUTED:
        return "REFUTED", "GROUNDING_REFUTED"
    if receipt.result is GroundingResult.INVALID:
        return "INVALID", "GROUNDING_RESULT_INVALID"
    return "UNKNOWN", "GROUNDING_RESULT_UNKNOWN"


def _denominator_grounding_result(
    reference: GroundingReference,
    denominator_digest: str,
    subject_id: str,
    members: list[dict[str, str]],
    evidence: Mapping[str, bytes],
    budget: _EvidenceBudget,
) -> tuple[str, str]:
    declaration_state, declaration_bytes = _lookup(
        reference.declaration_digest, evidence, budget
    )
    if declaration_state == "INVALID":
        return "INVALID", "DENOMINATOR_GROUNDING_DECLARATION_INVALID"
    if declaration_state == "LIMIT":
        return "UNKNOWN", "EVIDENCE_BUDGET_EXHAUSTED"
    if declaration_state == "MISSING":
        return "UNKNOWN", "DENOMINATOR_GROUNDING_DECLARATION_MISSING"
    assert declaration_bytes is not None
    try:
        declaration = decode_source_grounding_declaration(declaration_bytes)
    except (ValueError, TypeError, KeyError, AttributeError):
        return "INVALID", "DENOMINATOR_GROUNDING_DECLARATION_INVALID"
    proposition = declaration.ground_proposition
    expected_census_digest = _denominator_census_digest(subject_id, members)
    if declaration.source.digest == denominator_digest:
        return "INVALID", "DENOMINATOR_GROUNDING_CIRCULAR"
    if (
        proposition.predicate != "JSON_POINTER_EQUALS"
        or proposition.path != ("member_census_digest",)
        or proposition.expected != expected_census_digest
    ):
        return "INVALID", "DENOMINATOR_CENSUS_PROPOSITION_INVALID"
    return _grounding_result(reference, None, evidence, budget)


def assess_bounded_completeness(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> BoundedCompletenessReceipt:
    """Replay a bounded finite denominator and every declared member disposition."""

    declaration = decode_bounded_completeness_declaration(declaration_bytes)
    checks: dict[str, str] = {
        "denominator_binding": "UNKNOWN",
        "denominator_grounding": "UNKNOWN",
        "member_binding": "UNKNOWN",
        "member_recheck": "UNKNOWN",
        "observation_binding": "UNKNOWN",
        "profile_support": "UNKNOWN",
    }
    reasons: set[str] = set()
    assessments: list[MemberAssessment] = []
    budget = _EvidenceBudget(set())
    denominator_state, denominator_bytes = _lookup(
        declaration.denominator.digest, evidence, budget
    )
    observations_state, observations_bytes = _lookup(
        declaration.observations.digest, evidence, budget
    )
    checks["denominator_binding"] = denominator_state
    checks["observation_binding"] = observations_state
    if denominator_state != "BOUND":
        reasons.add(f"DENOMINATOR_{denominator_state}")
    if observations_state != "BOUND":
        reasons.add(f"OBSERVATIONS_{observations_state}")
    if denominator_bytes is not None and len(denominator_bytes) != declaration.denominator.size_bytes:
        checks["denominator_binding"] = "INVALID"
        reasons.add("DENOMINATOR_SIZE_INVALID")
    if observations_bytes is not None and len(observations_bytes) != declaration.observations.size_bytes:
        checks["observation_binding"] = "INVALID"
        reasons.add("OBSERVATIONS_SIZE_INVALID")
    checks["profile_support"] = "PASS" if declaration.profile_id == PROFILE_ID else "UNKNOWN"
    if checks["profile_support"] == "UNKNOWN":
        reasons.add("PROFILE_UNSUPPORTED")

    denominator_subject = ""
    members: list[dict[str, str]] = []
    observed: list[dict[str, str]] = []
    if denominator_bytes is not None:
        try:
            denominator_profile, denominator_subject, members = _denominator(
                denominator_bytes
            )
            if denominator_profile != declaration.profile_id:
                checks["denominator_binding"] = "INVALID"
                reasons.add("DENOMINATOR_PROFILE_INVALID")
        except BoundedCompletenessError:
            checks["denominator_binding"] = "INVALID"
            reasons.add("DENOMINATOR_INVALID")
    if observations_bytes is not None:
        try:
            observation_profile, denominator_digest, observed = _observations(observations_bytes)
            if observation_profile != declaration.profile_id or denominator_digest != declaration.denominator.digest:
                checks["observation_binding"] = "INVALID"
                reasons.add("OBSERVATION_CONTEXT_INVALID")
        except BoundedCompletenessError:
            checks["observation_binding"] = "INVALID"
            reasons.add("OBSERVATIONS_INVALID")

    if denominator_subject and members:
        denominator_grounding, denominator_reason = _denominator_grounding_result(
            declaration.denominator_grounding,
            declaration.denominator.digest,
            denominator_subject,
            members,
            evidence,
            budget,
        )
    else:
        denominator_grounding, denominator_reason = (
            "UNKNOWN",
            "DENOMINATOR_CENSUS_UNAVAILABLE",
        )
    checks["denominator_grounding"] = denominator_grounding
    if denominator_grounding != "ESTABLISHED":
        reasons.add(denominator_reason)

    expected_by_id = {item["member_id"]: item for item in members}
    observed_by_id = {item["member_id"]: item for item in observed}
    missing_member_ids = set(expected_by_id) - set(observed_by_id)
    extra_member_ids = set(observed_by_id) - set(expected_by_id)
    if extra_member_ids:
        checks["member_binding"] = "INVALID"
        reasons.add("OBSERVATION_MEMBER_OUTSIDE_DENOMINATOR")
    elif missing_member_ids:
        checks["member_binding"] = "INCOMPLETE"
        reasons.add("MEMBER_SET_INCOMPLETE")
    else:
        checks["member_binding"] = "PASS"
    decisive = True
    invalid_member = False
    for member_id in sorted(expected_by_id, key=lambda item: item.encode("utf-8")):
        member = expected_by_id[member_id]
        observation = observed_by_id.get(member_id)
        if observation is None:
            assessments.append(
                MemberAssessment(
                    member_id,
                    member["ground_proposition_digest"],
                    "UNKNOWN",
                    "NOT_CHECKED",
                )
            )
            decisive = False
            continue
        if observation["grounding_declaration_digest"] != member["grounding_declaration_digest"]:
            assessments.append(
                MemberAssessment(
                    member_id,
                    member["ground_proposition_digest"],
                    "INVALID",
                    "INVALID",
                )
            )
            invalid_member = True
            continue
        reference = GroundingReference(
            declaration_digest=member["grounding_declaration_digest"],
            receipt_digest=observation["grounding_receipt_digest"],
            ground_proposition_digest=member["ground_proposition_digest"],
        )
        state, reason = _grounding_result(reference, None, evidence, budget)
        if state not in {"ESTABLISHED", "REFUTED"}:
            decisive = False
            reasons.add(reason)
        if state == "INVALID":
            invalid_member = True
        assessments.append(
            MemberAssessment(
                member_id,
                member["ground_proposition_digest"],
                state,
                "DISPOSED" if state in {"ESTABLISHED", "REFUTED"} else "NOT_CHECKED" if state == "UNKNOWN" else "INVALID",
            )
        )
    checks["member_recheck"] = (
        "INVALID"
        if invalid_member or extra_member_ids
        else "PASS"
        if decisive and members
        else "INCOMPLETE"
    )
    if checks["member_recheck"] == "INCOMPLETE":
        reasons.add("MEMBER_RECHECK_INCOMPLETE")
    elif checks["member_recheck"] == "INVALID":
        reasons.add("MEMBER_RECHECK_INVALID")

    invalid = "INVALID" in checks.values()
    if invalid:
        result = CompletenessResult.INVALID
    elif (
        checks["profile_support"] != "PASS"
        or denominator_grounding == "UNKNOWN"
        or "LIMIT" in checks.values()
        or "EVIDENCE_BUDGET_EXHAUSTED" in reasons
        or checks["denominator_binding"] == "MISSING"
    ):
        result = CompletenessResult.UNKNOWN
    elif denominator_grounding != "ESTABLISHED":
        result = CompletenessResult.INVALID
    elif checks["member_binding"] == "PASS" and checks["member_recheck"] == "PASS":
        result = CompletenessResult.COMPLETE
    else:
        result = CompletenessResult.INCOMPLETE
    effectiveness = tuple(
        sorted(
            {
                "byte_limit": MAX_EVIDENCE_BYTES,
                "bytes_retained": budget.retained_bytes,
                "member_limit": MAX_MEMBERS,
                "members_examined": len(members),
                "object_byte_limit": MAX_OBJECT_BYTES,
                "procedure_id": "bounded-direct-replay-v1",
                "termination": "TERMINATED",
            }.items()
        )
    )
    return BoundedCompletenessReceipt(
        declaration_digest=digest_bytes(declaration_bytes),
        denominator_digest=declaration.denominator.digest,
        observations_digest=declaration.observations.digest,
        profile_id=declaration.profile_id,
        checker_coordinate=current_checker_coordinate(),
        result=result,
        checks=tuple(sorted(checks.items())),
        member_assessments=tuple(assessments),
        effectiveness=effectiveness,
        reason_codes=tuple(sorted(reasons)),
    )


def build_bounded_completeness_receipt(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> bytes:
    return canonical_bytes(assess_bounded_completeness(declaration_bytes, evidence).to_dict())


def decode_bounded_completeness_receipt(data: bytes) -> BoundedCompletenessReceipt:
    """Decode structure only; use receipt recheck before trusting any result."""

    value = _object(
        _decode(data),
        {
            "checker_coordinate",
            "checks",
            "declaration_digest",
            "denominator_digest",
            "effectiveness",
            "member_assessments",
            "observations_digest",
            "profile_id",
            "reason_codes",
            "residual_obligations",
            "result",
            "schema_version",
        },
        "bounded completeness receipt",
    )
    if value["schema_version"] != RECEIPT_SCHEMA:
        raise BoundedCompletenessError("unsupported receipt schema_version")
    coordinate = _object(
        value["checker_coordinate"],
        {"implementation_id", "implementation_version", "mechanism_profile_digest"},
        "checker_coordinate",
    )
    checker = CheckerCoordinate(
        _text(coordinate["implementation_id"], "checker implementation_id"),
        _text(coordinate["implementation_version"], "checker implementation_version"),
        _digest(coordinate["mechanism_profile_digest"], "checker mechanism_profile_digest"),
    )
    if checker != current_checker_coordinate():
        raise BoundedCompletenessError("receipt checker coordinate is unsupported")
    if type(value["checks"]) is not dict or type(value["effectiveness"]) is not dict:
        raise BoundedCompletenessError("receipt checks and effectiveness must be objects")
    expected_checks = {
        "denominator_binding",
        "denominator_grounding",
        "member_binding",
        "member_recheck",
        "observation_binding",
        "profile_support",
    }
    if set(value["checks"]) != expected_checks or any(
        type(item) is not str
        or item
        not in {
            "BOUND",
            "ESTABLISHED",
            "INCOMPLETE",
            "INVALID",
            "LIMIT",
            "MISSING",
            "PASS",
            "REFUTED",
            "UNKNOWN",
        }
        for item in value["checks"].values()
    ):
        raise BoundedCompletenessError("receipt checks are not exact supported states")
    expected_effectiveness = {
        "byte_limit",
        "bytes_retained",
        "member_limit",
        "members_examined",
        "object_byte_limit",
        "procedure_id",
        "termination",
    }
    if set(value["effectiveness"]) != expected_effectiveness:
        raise BoundedCompletenessError("receipt effectiveness fields are not exact")
    for name in {
        "byte_limit",
        "bytes_retained",
        "member_limit",
        "members_examined",
        "object_byte_limit",
    }:
        item = value["effectiveness"][name]
        if type(item) is not int or item < 0:
            raise BoundedCompletenessError("receipt effectiveness counts must be nonnegative integers")
    if value["effectiveness"]["procedure_id"] != "bounded-direct-replay-v1":
        raise BoundedCompletenessError("receipt procedure_id is unsupported")
    if value["effectiveness"]["termination"] != "TERMINATED":
        raise BoundedCompletenessError("receipt termination is not canonical")
    assessments = []
    if type(value["member_assessments"]) is not list or len(value["member_assessments"]) > MAX_MEMBERS:
        raise BoundedCompletenessError("receipt member assessments exceed their bound")
    for item in value["member_assessments"]:
        item = _object(
            item,
            {"disposition", "ground_proposition_digest", "grounding_result", "member_id"},
            "member assessment",
        )
        assessments.append(
            MemberAssessment(
                _text(item["member_id"], "member assessment member_id"),
                _digest(item["ground_proposition_digest"], "member assessment proposition"),
                _text(item["grounding_result"], "member assessment grounding_result"),
                _text(item["disposition"], "member assessment disposition"),
            )
        )
    if assessments != sorted(assessments, key=lambda item: item.member_id.encode("utf-8")):
        raise BoundedCompletenessError("receipt member assessments are not canonical")
    if len({item.member_id for item in assessments}) != len(assessments):
        raise BoundedCompletenessError("receipt member identifiers must be unique")
    if len({item.ground_proposition_digest for item in assessments}) != len(assessments):
        raise BoundedCompletenessError("receipt member propositions must be unique")
    for item in assessments:
        if item.grounding_result not in {"ESTABLISHED", "REFUTED", "UNKNOWN", "INVALID"}:
            raise BoundedCompletenessError("receipt grounding result is unsupported")
        expected_disposition = (
            "DISPOSED"
            if item.grounding_result in {"ESTABLISHED", "REFUTED"}
            else "NOT_CHECKED"
            if item.grounding_result == "UNKNOWN"
            else "INVALID"
        )
        if item.disposition != expected_disposition:
            raise BoundedCompletenessError("receipt disposition does not match grounding result")
    try:
        result = CompletenessResult(value["result"])
    except ValueError as error:
        raise BoundedCompletenessError("unsupported completeness result") from error
    if value["residual_obligations"] != list(_RESIDUALS):
        raise BoundedCompletenessError("receipt residual obligations are not canonical")
    if (
        type(value["reason_codes"]) is not list
        or value["reason_codes"] != sorted(set(value["reason_codes"]))
        or any(type(item) is not str or not item for item in value["reason_codes"])
    ):
        raise BoundedCompletenessError("receipt reason codes must be sorted unique")
    if value["effectiveness"]["byte_limit"] != MAX_EVIDENCE_BYTES:
        raise BoundedCompletenessError("receipt evidence byte limit is not canonical")
    if value["effectiveness"]["member_limit"] != MAX_MEMBERS:
        raise BoundedCompletenessError("receipt member limit is not canonical")
    if value["effectiveness"]["object_byte_limit"] != MAX_OBJECT_BYTES:
        raise BoundedCompletenessError("receipt object byte limit is not canonical")
    if value["effectiveness"]["members_examined"] != len(assessments):
        raise BoundedCompletenessError("receipt member count does not match assessments")
    if value["effectiveness"]["bytes_retained"] > MAX_EVIDENCE_BYTES:
        raise BoundedCompletenessError("receipt retained bytes exceed the mechanism limit")
    if result is CompletenessResult.COMPLETE and not (
        value["profile_id"] == PROFILE_ID
        and value["reason_codes"] == []
        and value["effectiveness"]["bytes_retained"] > 0
        and value["checks"]
        == {
            "denominator_binding": "BOUND",
            "denominator_grounding": "ESTABLISHED",
            "member_binding": "PASS",
            "member_recheck": "PASS",
            "observation_binding": "BOUND",
            "profile_support": "PASS",
        }
        and assessments
        and all(item.disposition == "DISPOSED" for item in assessments)
    ):
        raise BoundedCompletenessError("COMPLETE receipt has contradictory evidence states")
    receipt = BoundedCompletenessReceipt(
        declaration_digest=_digest(value["declaration_digest"], "receipt declaration_digest"),
        denominator_digest=_digest(value["denominator_digest"], "receipt denominator_digest"),
        observations_digest=_digest(value["observations_digest"], "receipt observations_digest"),
        profile_id=_text(value["profile_id"], "receipt profile_id"),
        checker_coordinate=checker,
        result=result,
        checks=tuple(sorted(value["checks"].items())),
        member_assessments=tuple(assessments),
        effectiveness=tuple(sorted(value["effectiveness"].items())),
        reason_codes=tuple(value["reason_codes"]),
    )
    if canonical_bytes(receipt.to_dict()) != data:
        raise BoundedCompletenessError("receipt is not an exact canonical typed record")
    return receipt


def recheck_bounded_completeness_receipt(
    declaration_bytes: bytes, receipt_bytes: bytes, evidence: Mapping[str, bytes]
) -> BoundedCompletenessReceipt:
    supplied = decode_bounded_completeness_receipt(receipt_bytes)
    expected = assess_bounded_completeness(declaration_bytes, evidence)
    if supplied != expected or canonical_bytes(supplied.to_dict()) != receipt_bytes:
        raise BoundedCompletenessError("receipt does not equal the deterministic replay")
    return supplied


__all__ = [
    "BoundedCompletenessDeclaration",
    "BoundedCompletenessError",
    "BoundedCompletenessReceipt",
    "CompletenessResult",
    "ExactBytesReference",
    "GroundingReference",
    "MemberAssessment",
    "assess_bounded_completeness",
    "build_bounded_completeness_receipt",
    "canonical_bytes",
    "current_checker_coordinate",
    "decode_bounded_completeness_declaration",
    "decode_bounded_completeness_receipt",
    "digest_bytes",
    "mechanism_profile_bytes",
    "mechanism_profile_digest",
    "recheck_bounded_completeness_receipt",
]
