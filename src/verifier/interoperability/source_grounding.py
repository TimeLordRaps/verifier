"""Experimental source grounding for Verifier Standard (VSTD) evidence.

JavaScript Object Notation (JSON) records, Secure Hash Algorithm 256-bit
(SHA-256) identities, and Unicode Transformation Format, 8-bit (UTF-8) text are
dimensionless.  A serialized identifier (ID) names a mechanism or proposition.
This sidecar replays one bounded,
registered interpretation over exact retained source bytes.  It does not infer
grounding from a declaration, certificate authorship, or a claimed verdict.
Producer independence, historical execution, completeness, authority, and
runtime correspondence remain explicitly unestablished.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping


DECLARATION_SCHEMA = "verifier-source-grounding-1"
CERTIFICATE_SCHEMA = "verifier-source-grounding-certificate-1"
RECEIPT_SCHEMA = "verifier-source-grounding-receipt-1"
MECHANISM_PROFILE_SCHEMA = "verifier-source-grounding-mechanism-profile-1"
INTERPRETATION_PROFILE = "verifier-canonical-json-interpretation-1"
MECHANISM_ID = "canonical-json-pointer-equality-v1"
CHECKER_IMPLEMENTATION = "verifier.interoperability.source_grounding"
CHECKER_VERSION = "0.1"
MAX_RECORD_BYTES = 65536
MAX_SOURCE_BYTES = 1048576
MAX_EVIDENCE_BYTES = MAX_SOURCE_BYTES + MAX_RECORD_BYTES
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4096
MAX_TEXT_BYTES = 512
MAX_ITEMS = 64
MAX_INTEGER_ABS = 9223372036854775807
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MISSING = object()
_RESIDUALS = (
    "AUTHORITY_NOT_ESTABLISHED",
    "COMPLETENESS_NOT_ESTABLISHED",
    "HISTORICAL_EXECUTION_NOT_ESTABLISHED",
    "PRODUCER_INDEPENDENCE_NOT_ESTABLISHED",
    "RUNTIME_CORRESPONDENCE_NOT_ESTABLISHED",
)


class SourceGroundingError(ValueError):
    """A bounded source-grounding record is not valid canonical input."""


class GroundingResult(str, Enum):
    """Fail-closed result of the exact bounded qualification."""

    ESTABLISHED = "ESTABLISHED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class ExactBytesReference:
    digest: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class SemanticFrame:
    frame_id: str
    proposition_language: str
    vocabulary_digest: str
    facets: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "facets": list(self.facets),
            "frame_id": self.frame_id,
            "proposition_language": self.proposition_language,
            "vocabulary_digest": self.vocabulary_digest,
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
class Interpretation:
    profile_id: str
    mechanism_id: str
    mechanism_profile_digest: str
    checker_coordinate: CheckerCoordinate

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker_coordinate": self.checker_coordinate.to_dict(),
            "mechanism_id": self.mechanism_id,
            "mechanism_profile_digest": self.mechanism_profile_digest,
            "profile_id": self.profile_id,
        }


@dataclass(frozen=True)
class GroundProposition:
    proposition_id: str
    predicate: str
    path: tuple[str, ...]
    expected: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "path": list(self.path),
            "predicate": self.predicate,
            "proposition_id": self.proposition_id,
        }


@dataclass(frozen=True)
class CertificateReference:
    digest: str
    size_bytes: int
    certificate_kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_kind": self.certificate_kind,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class SourceGroundingDeclaration:
    source: ExactBytesReference
    semantic_frame: SemanticFrame
    interpretation: Interpretation
    ground_proposition: GroundProposition
    certificate: CertificateReference
    assumptions: tuple[str, ...]
    declarer_coordinate: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumptions": list(self.assumptions),
            "certificate": self.certificate.to_dict(),
            "declarer_coordinate": self.declarer_coordinate,
            "ground_proposition": self.ground_proposition.to_dict(),
            "interpretation": self.interpretation.to_dict(),
            "schema_version": DECLARATION_SCHEMA,
            "semantic_frame": self.semantic_frame.to_dict(),
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class SourceGroundingReceipt:
    declaration_digest: str
    source_digest: str
    certificate_digest: str
    interpretation_profile_digest: str
    checker_coordinate: CheckerCoordinate
    result: GroundingResult
    reason_codes: tuple[str, ...]
    checks: tuple[tuple[str, str], ...]
    assumptions: tuple[str, ...]
    residual_obligations: tuple[str, ...] = _RESIDUALS

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumptions": list(self.assumptions),
            "certificate_digest": self.certificate_digest,
            "checker_coordinate": self.checker_coordinate.to_dict(),
            "checks": {key: value for key, value in self.checks},
            "declaration_digest": self.declaration_digest,
            "interpretation_profile_digest": self.interpretation_profile_digest,
            "reason_codes": list(self.reason_codes),
            "residual_obligations": list(self.residual_obligations),
            "result": self.result.value,
            "schema_version": RECEIPT_SCHEMA,
            "source_digest": self.source_digest,
        }


def canonical_bytes(value: Any) -> bytes:
    """Encode a JSON value canonically for exact record identity."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 identity of exact bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceGroundingError("duplicate JSON object key")
        result[key] = value
    return result


def _bounded_json(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise SourceGroundingError("JSON value exceeds depth or node bound")
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if abs(item) > MAX_INTEGER_ABS:
                raise SourceGroundingError("JSON integer exceeds its signed 64-bit bound")
            continue
        if type(item) is str:
            _text(item)
        elif type(item) is list:
            if len(item) > MAX_ITEMS:
                raise SourceGroundingError("JSON list exceeds item bound")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            if len(item) > MAX_ITEMS:
                raise SourceGroundingError("JSON object exceeds item bound")
            for key, child in item.items():
                _text(key)
                pending.append((child, depth + 1))
        else:
            raise SourceGroundingError("JSON values must not contain floats or extensions")


def _decode_canonical(data: bytes, limit: int = MAX_RECORD_BYTES) -> dict[str, Any]:
    if type(data) is not bytes:
        raise SourceGroundingError("record must be immutable bytes")
    if len(data) > limit:
        raise SourceGroundingError("record exceeds byte bound")
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
                raise SourceGroundingError("record exceeds JSON nesting bound")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        _bounded_json(value)
        if type(value) is not dict or canonical_bytes(value) != data:
            raise SourceGroundingError("record must be an exact canonical JSON object")
        return value
    except SourceGroundingError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SourceGroundingError(f"invalid bounded JSON record: {error}") from error


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise SourceGroundingError(f"{label} must have exactly its defined fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise SourceGroundingError("text must be nonempty and within its UTF-8 byte bound")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SourceGroundingError("digest must be an exact lowercase SHA-256 identity")
    return value


def _count(value: Any, upper: int) -> int:
    if type(value) is not int or not 0 <= value <= upper:
        raise SourceGroundingError("byte count must be a bounded nonnegative integer")
    return value


def _sorted_strings(value: Any, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_ITEMS or (not allow_empty and not value):
        raise SourceGroundingError("string set has an invalid item count")
    strings = tuple(_text(item) for item in value)
    if list(strings) != sorted(set(strings), key=lambda item: item.encode("utf-8")):
        raise SourceGroundingError("string set must be unique and in UTF-8 byte order")
    return strings


def _path(value: Any) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAX_JSON_DEPTH:
        raise SourceGroundingError("path must contain one to the depth-bound number of components")
    return tuple(_text(item) for item in value)


def _reference(value: Any, upper: int) -> ExactBytesReference:
    item = _object(value, {"digest", "size_bytes"}, "exact bytes reference")
    return ExactBytesReference(_digest(item["digest"]), _count(item["size_bytes"], upper))


def _frame(value: Any) -> SemanticFrame:
    item = _object(
        value,
        {"facets", "frame_id", "proposition_language", "vocabulary_digest"},
        "semantic frame",
    )
    return SemanticFrame(
        _text(item["frame_id"]),
        _text(item["proposition_language"]),
        _digest(item["vocabulary_digest"]),
        _sorted_strings(item["facets"], allow_empty=False),
    )


def _checker_coordinate(value: Any) -> CheckerCoordinate:
    item = _object(
        value,
        {"implementation_id", "implementation_version", "mechanism_profile_digest"},
        "checker coordinate",
    )
    return CheckerCoordinate(
        _text(item["implementation_id"]),
        _text(item["implementation_version"]),
        _digest(item["mechanism_profile_digest"]),
    )


def source_grounding_mechanism_profile_bytes() -> bytes:
    """Return the registered mechanism rules, not an execution receipt."""

    return canonical_bytes({
        "accepted_frame_id": "CANONICAL-JSON-OBJECT-0.1",
        "accepted_language": "CANONICAL_JSON_OBJECT",
        "accepted_predicate": "JSON_POINTER_EQUALS",
        "canonical_records_required": True,
        "certificate_replay_required": True,
        "max_json_depth": MAX_JSON_DEPTH,
        "max_json_nodes": MAX_JSON_NODES,
        "max_source_bytes": MAX_SOURCE_BYTES,
        "mechanism_id": MECHANISM_ID,
        "schema_version": MECHANISM_PROFILE_SCHEMA,
    })


def source_grounding_mechanism_profile_digest() -> str:
    return digest_bytes(source_grounding_mechanism_profile_bytes())


def current_checker_coordinate() -> CheckerCoordinate:
    return CheckerCoordinate(
        CHECKER_IMPLEMENTATION,
        CHECKER_VERSION,
        source_grounding_mechanism_profile_digest(),
    )


def decode_source_grounding_declaration(data: bytes) -> SourceGroundingDeclaration:
    """Decode strict canonical declaration bytes without establishing grounding."""

    value = _object(
        _decode_canonical(data),
        {
            "assumptions",
            "certificate",
            "declarer_coordinate",
            "ground_proposition",
            "interpretation",
            "schema_version",
            "semantic_frame",
            "source",
        },
        "source grounding declaration",
    )
    if value["schema_version"] != DECLARATION_SCHEMA:
        raise SourceGroundingError("unsupported source grounding schema_version")
    source = _reference(value["source"], MAX_SOURCE_BYTES)
    frame = _frame(value["semantic_frame"])
    raw_interpretation = _object(
        value["interpretation"],
        {"checker_coordinate", "mechanism_id", "mechanism_profile_digest", "profile_id"},
        "interpretation",
    )
    interpretation = Interpretation(
        _text(raw_interpretation["profile_id"]),
        _text(raw_interpretation["mechanism_id"]),
        _digest(raw_interpretation["mechanism_profile_digest"]),
        _checker_coordinate(raw_interpretation["checker_coordinate"]),
    )
    raw_proposition = _object(
        value["ground_proposition"],
        {"expected", "path", "predicate", "proposition_id"},
        "ground proposition",
    )
    _bounded_json(raw_proposition["expected"])
    proposition = GroundProposition(
        _text(raw_proposition["proposition_id"]),
        _text(raw_proposition["predicate"]),
        _path(raw_proposition["path"]),
        raw_proposition["expected"],
    )
    raw_certificate = _object(
        value["certificate"], {"certificate_kind", "digest", "size_bytes"}, "certificate reference"
    )
    kind = _text(raw_certificate["certificate_kind"])
    if kind not in {"DERIVATION", "TRANSLATION"}:
        raise SourceGroundingError("unsupported source grounding certificate kind")
    certificate = CertificateReference(
        _digest(raw_certificate["digest"]),
        _count(raw_certificate["size_bytes"], MAX_RECORD_BYTES),
        kind,
    )
    return SourceGroundingDeclaration(
        source,
        frame,
        interpretation,
        proposition,
        certificate,
        _sorted_strings(value["assumptions"]),
        _text(value["declarer_coordinate"]),
    )


def _get_evidence(
    reference: ExactBytesReference | CertificateReference,
    evidence: Mapping[str, bytes],
    upper: int,
) -> tuple[str, bytes | None]:
    try:
        payload = evidence[reference.digest]
    except (KeyError, TypeError):
        return "UNKNOWN", None
    if type(payload) is not bytes:
        return "INVALID", None
    if len(payload) > upper or len(payload) + MAX_RECORD_BYTES > MAX_EVIDENCE_BYTES:
        return "UNKNOWN", None
    if len(payload) != reference.size_bytes or digest_bytes(payload) != reference.digest:
        return "INVALID", None
    return "BOUND", payload


def _profile_digest(declaration: SourceGroundingDeclaration) -> str:
    return digest_bytes(canonical_bytes(declaration.interpretation.to_dict()))


def _semantic_frame_digest(declaration: SourceGroundingDeclaration) -> str:
    return digest_bytes(canonical_bytes(declaration.semantic_frame.to_dict()))


def _proposition_digest(declaration: SourceGroundingDeclaration) -> str:
    return digest_bytes(canonical_bytes(declaration.ground_proposition.to_dict()))


def _resolve(source: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = source
    for component in path:
        if type(current) is not dict or component not in current:
            return _MISSING
        current = current[component]
    return current


def _decode_certificate(data: bytes) -> dict[str, Any]:
    value = _object(
        _decode_canonical(data),
        {
            "certificate_kind",
            "checker_coordinate",
            "evidence_origin",
            "ground_proposition_digest",
            "interpretation_profile_digest",
            "mechanism_id",
            "observation",
            "producer_coordinate",
            "result",
            "schema_version",
            "semantic_frame_digest",
            "source_digest",
        },
        "source grounding certificate",
    )
    if value["schema_version"] != CERTIFICATE_SCHEMA:
        raise SourceGroundingError("unsupported source grounding certificate schema_version")
    if value["certificate_kind"] not in {"DERIVATION", "TRANSLATION"}:
        raise SourceGroundingError("unsupported certificate kind")
    if value["evidence_origin"] != "MECHANISM_EXECUTION":
        raise SourceGroundingError("certificate evidence must come from mechanism execution")
    for field in (
        "ground_proposition_digest",
        "interpretation_profile_digest",
        "semantic_frame_digest",
        "source_digest",
    ):
        _digest(value[field])
    _text(value["mechanism_id"])
    _text(value["producer_coordinate"])
    _checker_coordinate(value["checker_coordinate"])
    observation = _object(value["observation"], {"path", "state", "value"}, "observation")
    _path(observation["path"])
    if observation["state"] not in {"ABSENT", "VALUE"}:
        raise SourceGroundingError("unsupported observation state")
    if observation["state"] == "ABSENT" and observation["value"] is not None:
        raise SourceGroundingError("absent observation must carry a null value")
    _bounded_json(observation["value"])
    if value["result"] not in {"ESTABLISHED", "REFUTED"}:
        raise SourceGroundingError("certificate result must be established or refuted")
    return value


def expected_source_grounding_certificate(
    declaration: SourceGroundingDeclaration,
    source_bytes: bytes,
    producer_coordinate: str,
) -> bytes:
    """Replay the registered mechanism and return its expected certificate bytes.

    This deterministic helper does not establish historical execution or producer
    independence.  Qualification replays the same bounded proposition from the
    retained source rather than trusting the returned status word.
    """

    _text(producer_coordinate)
    source = _decode_canonical(source_bytes, MAX_SOURCE_BYTES)
    observed = _resolve(source, declaration.ground_proposition.path)
    state = "ABSENT" if observed is _MISSING else "VALUE"
    value = None if observed is _MISSING else observed
    result = (
        "ESTABLISHED"
        if observed is not _MISSING
        and canonical_bytes(observed) == canonical_bytes(declaration.ground_proposition.expected)
        else "REFUTED"
    )
    return canonical_bytes({
        "certificate_kind": declaration.certificate.certificate_kind,
        "checker_coordinate": declaration.interpretation.checker_coordinate.to_dict(),
        "evidence_origin": "MECHANISM_EXECUTION",
        "ground_proposition_digest": _proposition_digest(declaration),
        "interpretation_profile_digest": _profile_digest(declaration),
        "mechanism_id": declaration.interpretation.mechanism_id,
        "observation": {
            "path": list(declaration.ground_proposition.path),
            "state": state,
            "value": value,
        },
        "producer_coordinate": producer_coordinate,
        "result": result,
        "schema_version": CERTIFICATE_SCHEMA,
        "semantic_frame_digest": _semantic_frame_digest(declaration),
        "source_digest": declaration.source.digest,
    })


def qualify_source_grounding(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> SourceGroundingReceipt:
    """Recheck exact evidence and fail closed at every unsupported seam."""

    declaration = decode_source_grounding_declaration(declaration_bytes)
    declaration_digest = digest_bytes(declaration_bytes)
    checks: dict[str, str] = {
        "certificate_binding": "UNKNOWN",
        "certificate_recheck": "UNKNOWN",
        "frame_compatibility": "UNKNOWN",
        "mechanism_support": "UNKNOWN",
        "proposition_evaluation": "UNKNOWN",
        "source_binding": "UNKNOWN",
    }
    reasons: set[str] = set()
    result = GroundingResult.UNKNOWN

    circular = (
        declaration.source.digest in {declaration_digest, declaration.certificate.digest}
        or declaration.certificate.digest == declaration_digest
    )
    if circular:
        checks["source_binding"] = "INVALID"
        checks["certificate_binding"] = "INVALID"
        reasons.add("CIRCULAR_EVIDENCE_BINDING")
        result = GroundingResult.INVALID

    source_state, source_bytes = _get_evidence(declaration.source, evidence, MAX_SOURCE_BYTES)
    certificate_state, certificate_bytes = _get_evidence(
        declaration.certificate, evidence, MAX_RECORD_BYTES
    )
    checks["source_binding"] = "INVALID" if circular else source_state
    checks["certificate_binding"] = "INVALID" if circular else certificate_state
    for label, state in (("SOURCE", source_state), ("CERTIFICATE", certificate_state)):
        if state != "BOUND":
            reasons.add(f"{label}_{state}")
            if state == "INVALID":
                result = GroundingResult.INVALID

    coordinate = current_checker_coordinate()
    supported = (
        declaration.interpretation.profile_id == INTERPRETATION_PROFILE
        and declaration.interpretation.mechanism_id == MECHANISM_ID
        and declaration.interpretation.mechanism_profile_digest
        == source_grounding_mechanism_profile_digest()
        and declaration.interpretation.checker_coordinate == coordinate
        and declaration.ground_proposition.predicate == "JSON_POINTER_EQUALS"
    )
    checks["mechanism_support"] = "SUPPORTED" if supported else "UNKNOWN"
    if not supported:
        reasons.add("MECHANISM_OR_PROFILE_UNSUPPORTED")

    frame_supported = (
        declaration.semantic_frame.frame_id == "CANONICAL-JSON-OBJECT-0.1"
        and declaration.semantic_frame.proposition_language == "CANONICAL_JSON_OBJECT"
        and declaration.ground_proposition.path[0] in declaration.semantic_frame.facets
    )
    checks["frame_compatibility"] = "COMPATIBLE" if frame_supported else "UNKNOWN"
    if not frame_supported:
        reasons.add("SEMANTIC_FRAME_UNSUPPORTED")

    if result is not GroundingResult.INVALID and source_bytes is not None and certificate_bytes is not None:
        try:
            source = _decode_canonical(source_bytes, MAX_SOURCE_BYTES)
            if tuple(sorted(source, key=lambda item: item.encode("utf-8"))) != declaration.semantic_frame.facets:
                raise SourceGroundingError("source top-level facets do not match its semantic frame")
            certificate = _decode_certificate(certificate_bytes)
            if certificate["certificate_kind"] != declaration.certificate.certificate_kind:
                raise SourceGroundingError("certificate kind does not match its declaration")
            replay = expected_source_grounding_certificate(
                declaration, source_bytes, certificate["producer_coordinate"]
            )
            if replay != certificate_bytes:
                checks["certificate_recheck"] = "INVALID"
                reasons.add("CERTIFICATE_RECHECK_INVALID")
                result = GroundingResult.INVALID
            elif supported and frame_supported:
                checks["certificate_recheck"] = "REPRODUCED"
                result = GroundingResult(certificate["result"])
                checks["proposition_evaluation"] = certificate["result"]
        except SourceGroundingError:
            checks["certificate_recheck"] = "INVALID"
            reasons.add("SOURCE_OR_CERTIFICATE_INVALID")
            result = GroundingResult.INVALID

    if result is GroundingResult.UNKNOWN and not reasons:
        reasons.add("EVIDENCE_UNKNOWN")
    return SourceGroundingReceipt(
        declaration_digest,
        declaration.source.digest,
        declaration.certificate.digest,
        _profile_digest(declaration),
        coordinate,
        result,
        tuple(sorted(reasons)),
        tuple(sorted(checks.items())),
        declaration.assumptions,
    )


def build_source_grounding_receipt(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> bytes:
    """Build a deterministic unsigned receipt for the current replay."""

    return canonical_bytes(qualify_source_grounding(declaration_bytes, evidence).to_dict())


def decode_source_grounding_receipt(data: bytes) -> SourceGroundingReceipt:
    """Decode a receipt structurally; decoding alone establishes no result."""

    value = _object(
        _decode_canonical(data),
        {
            "assumptions",
            "certificate_digest",
            "checker_coordinate",
            "checks",
            "declaration_digest",
            "interpretation_profile_digest",
            "reason_codes",
            "residual_obligations",
            "result",
            "schema_version",
            "source_digest",
        },
        "source grounding receipt",
    )
    if value["schema_version"] != RECEIPT_SCHEMA:
        raise SourceGroundingError("unsupported source grounding receipt schema_version")
    checks = value["checks"]
    expected_checks = {
        "certificate_binding",
        "certificate_recheck",
        "frame_compatibility",
        "mechanism_support",
        "proposition_evaluation",
        "source_binding",
    }
    if type(checks) is not dict or set(checks) != expected_checks:
        raise SourceGroundingError("receipt checks must have exactly their defined fields")
    check_items = tuple(sorted((_text(key), _text(item)) for key, item in checks.items()))
    try:
        result = GroundingResult(value["result"])
    except (TypeError, ValueError) as error:
        raise SourceGroundingError("unsupported source grounding result") from error
    residuals = _sorted_strings(value["residual_obligations"], allow_empty=False)
    if residuals != _RESIDUALS:
        raise SourceGroundingError("source grounding residual obligations are not exact")
    return SourceGroundingReceipt(
        _digest(value["declaration_digest"]),
        _digest(value["source_digest"]),
        _digest(value["certificate_digest"]),
        _digest(value["interpretation_profile_digest"]),
        _checker_coordinate(value["checker_coordinate"]),
        result,
        _sorted_strings(value["reason_codes"]),
        check_items,
        _sorted_strings(value["assumptions"]),
        residuals,
    )


def recheck_source_grounding_receipt(
    declaration_bytes: bytes,
    receipt_bytes: bytes,
    evidence: Mapping[str, bytes],
) -> SourceGroundingReceipt:
    """Require exact receipt reproduction from the current retained evidence."""

    receipt = decode_source_grounding_receipt(receipt_bytes)
    rebuilt = build_source_grounding_receipt(declaration_bytes, evidence)
    if receipt_bytes != rebuilt:
        raise SourceGroundingError("SOURCE_GROUNDING_RECEIPT_NOT_REPRODUCED")
    return receipt
