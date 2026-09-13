"""Experimental relation-boundary replay for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) records, Secure Hash Algorithm 256-bit
(SHA-256) identities, and Unicode Transformation Format, 8-bit (UTF-8) text are
dimensionless.  A serialized identifier (ID) names a mechanism or proposition.
The registered mechanism compares
declared facets in exact source and target proposition bytes.  A receipt exposes
preserved and lost information; it never upgrades a bounded map to semantic
equivalence, completeness, authority, or general translation correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .source_grounding import (
    CheckerCoordinate,
    ExactBytesReference,
    MAX_ITEMS,
    MAX_RECORD_BYTES,
    MAX_SOURCE_BYTES,
    SemanticFrame,
    SourceGroundingError,
    _checker_coordinate,
    _count,
    _decode_canonical,
    _digest,
    _frame,
    _object,
    _sorted_strings,
    _text,
    canonical_bytes,
    digest_bytes,
)


DECLARATION_SCHEMA = "VSTD-RELATION-BOUNDARY-0.1"
EVIDENCE_SCHEMA = "VSTD-RELATION-BOUNDARY-EVIDENCE-0.1"
RECEIPT_SCHEMA = "VSTD-RELATION-BOUNDARY-RECEIPT-0.1"
MECHANISM_PROFILE_SCHEMA = "VSTD-RELATION-BOUNDARY-MECHANISM-PROFILE-0.1"
MECHANISM_ID = "canonical-json-facet-map-v1"
CHECKER_IMPLEMENTATION = "verifier.interoperability.relation_boundary"
CHECKER_VERSION = "0.1"
MAX_RELATION_ARTIFACT_BYTES = MAX_SOURCE_BYTES
_RESIDUALS = (
    "AUTHORITY_NOT_ESTABLISHED",
    "COMPLETENESS_NOT_ESTABLISHED",
    "GENERAL_TRANSLATION_NOT_ESTABLISHED",
    "HISTORICAL_EXECUTION_NOT_ESTABLISHED",
    "PRODUCER_INDEPENDENCE_NOT_ESTABLISHED",
    "RUNTIME_CORRESPONDENCE_NOT_ESTABLISHED",
)


class RelationBoundaryError(ValueError):
    """A bounded relation-boundary record is not valid canonical input."""


class RelationResult(str, Enum):
    """Fail-closed result of the exact bounded relation qualification."""

    ESTABLISHED = "ESTABLISHED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class PropositionEndpoint:
    proposition_id: str
    artifact: ExactBytesReference
    semantic_frame: SemanticFrame

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "proposition_id": self.proposition_id,
            "semantic_frame": self.semantic_frame.to_dict(),
        }


@dataclass(frozen=True)
class FacetPreservation:
    source_facet: str
    target_facet: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source_facet": self.source_facet,
            "target_facet": self.target_facet,
        }


@dataclass(frozen=True)
class TranslationMechanism:
    mechanism_id: str
    mechanism_profile_digest: str
    checker_coordinate: CheckerCoordinate

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker_coordinate": self.checker_coordinate.to_dict(),
            "mechanism_id": self.mechanism_id,
            "mechanism_profile_digest": self.mechanism_profile_digest,
        }


@dataclass(frozen=True)
class RelationEvidenceReference:
    digest: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class RelationBoundaryDeclaration:
    source: PropositionEndpoint
    target: PropositionEndpoint
    translation: TranslationMechanism
    evidence: RelationEvidenceReference
    consumed_facets: tuple[str, ...]
    preservation_map: tuple[FacetPreservation, ...]
    loss_map: tuple[str, ...]
    assumptions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumptions": list(self.assumptions),
            "consumed_facets": list(self.consumed_facets),
            "evidence": self.evidence.to_dict(),
            "loss_map": list(self.loss_map),
            "preservation_map": [item.to_dict() for item in self.preservation_map],
            "schema_version": DECLARATION_SCHEMA,
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "translation": self.translation.to_dict(),
        }


@dataclass(frozen=True)
class RelationBoundaryReceipt:
    declaration_digest: str
    source_digest: str
    target_digest: str
    evidence_digest: str
    mechanism_profile_digest: str
    checker_coordinate: CheckerCoordinate
    result: RelationResult
    information_loss: str
    reason_codes: tuple[str, ...]
    checks: tuple[tuple[str, str], ...]
    consumed_facets: tuple[str, ...]
    preservation_map: tuple[FacetPreservation, ...]
    loss_map: tuple[str, ...]
    assumptions: tuple[str, ...]
    residual_obligations: tuple[str, ...] = _RESIDUALS

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumptions": list(self.assumptions),
            "checker_coordinate": self.checker_coordinate.to_dict(),
            "checks": {key: value for key, value in self.checks},
            "consumed_facets": list(self.consumed_facets),
            "declaration_digest": self.declaration_digest,
            "evidence_digest": self.evidence_digest,
            "information_loss": self.information_loss,
            "loss_map": list(self.loss_map),
            "mechanism_profile_digest": self.mechanism_profile_digest,
            "preservation_map": [item.to_dict() for item in self.preservation_map],
            "reason_codes": list(self.reason_codes),
            "residual_obligations": list(self.residual_obligations),
            "result": self.result.value,
            "schema_version": RECEIPT_SCHEMA,
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
        }


def relation_boundary_mechanism_profile_bytes() -> bytes:
    """Return the exact registered facet-map rules, not an execution claim."""

    return canonical_bytes({
        "accepted_frame_id": "CANONICAL-JSON-OBJECT-0.1",
        "accepted_language": "CANONICAL_JSON_OBJECT",
        "canonical_records_required": True,
        "evidence_replay_required": True,
        "explicit_loss_required": True,
        "max_facets": MAX_ITEMS,
        "max_relation_artifact_bytes": MAX_RELATION_ARTIFACT_BYTES,
        "mechanism_id": MECHANISM_ID,
        "schema_version": MECHANISM_PROFILE_SCHEMA,
    })


def relation_boundary_mechanism_profile_digest() -> str:
    return digest_bytes(relation_boundary_mechanism_profile_bytes())


def current_checker_coordinate() -> CheckerCoordinate:
    return CheckerCoordinate(
        CHECKER_IMPLEMENTATION,
        CHECKER_VERSION,
        relation_boundary_mechanism_profile_digest(),
    )


def _reference(value: Any, label: str, upper: int) -> ExactBytesReference:
    try:
        item = _object(value, {"digest", "size_bytes"}, label)
        return ExactBytesReference(_digest(item["digest"]), _count(item["size_bytes"], upper))
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error


def _endpoint(value: Any, label: str) -> PropositionEndpoint:
    try:
        item = _object(value, {"artifact", "proposition_id", "semantic_frame"}, label)
        return PropositionEndpoint(
            _text(item["proposition_id"]),
            _reference(item["artifact"], f"{label} artifact", MAX_RELATION_ARTIFACT_BYTES),
            _frame(item["semantic_frame"]),
        )
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error


def _preservation_map(value: Any) -> tuple[FacetPreservation, ...]:
    if type(value) is not list or len(value) > MAX_ITEMS:
        raise RelationBoundaryError("preservation map exceeds its item bound")
    result: list[FacetPreservation] = []
    try:
        for raw in value:
            item = _object(raw, {"source_facet", "target_facet"}, "facet preservation")
            result.append(FacetPreservation(_text(item["source_facet"]), _text(item["target_facet"])))
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error
    pairs = [(item.source_facet, item.target_facet) for item in result]
    if pairs != sorted(set(pairs), key=lambda pair: (pair[0].encode("utf-8"), pair[1].encode("utf-8"))):
        raise RelationBoundaryError("preservation map must be unique and in source/target UTF-8 byte order")
    if len({item.source_facet for item in result}) != len(result):
        raise RelationBoundaryError("a source facet may be preserved only once")
    if len({item.target_facet for item in result}) != len(result):
        raise RelationBoundaryError("a target facet may receive only one source facet")
    return tuple(result)


def decode_relation_boundary_declaration(data: bytes) -> RelationBoundaryDeclaration:
    """Decode a strict declaration without accepting its claimed relationship."""

    try:
        value = _object(
            _decode_canonical(data),
            {
                "assumptions",
                "consumed_facets",
                "evidence",
                "loss_map",
                "preservation_map",
                "schema_version",
                "source",
                "target",
                "translation",
            },
            "relation boundary declaration",
        )
        if value["schema_version"] != DECLARATION_SCHEMA:
            raise RelationBoundaryError("unsupported relation boundary schema_version")
        source = _endpoint(value["source"], "source proposition")
        target = _endpoint(value["target"], "target proposition")
        raw_translation = _object(
            value["translation"],
            {"checker_coordinate", "mechanism_id", "mechanism_profile_digest"},
            "translation mechanism",
        )
        translation = TranslationMechanism(
            _text(raw_translation["mechanism_id"]),
            _digest(raw_translation["mechanism_profile_digest"]),
            _checker_coordinate(raw_translation["checker_coordinate"]),
        )
        raw_evidence = _reference(value["evidence"], "relation evidence", MAX_RECORD_BYTES)
        return RelationBoundaryDeclaration(
            source,
            target,
            translation,
            RelationEvidenceReference(raw_evidence.digest, raw_evidence.size_bytes),
            _sorted_strings(value["consumed_facets"], allow_empty=False),
            _preservation_map(value["preservation_map"]),
            _sorted_strings(value["loss_map"]),
            _sorted_strings(value["assumptions"]),
        )
    except RelationBoundaryError:
        raise
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error


def _translation_digest(declaration: RelationBoundaryDeclaration) -> str:
    return digest_bytes(canonical_bytes(declaration.translation.to_dict()))


def _frame_digest(endpoint: PropositionEndpoint) -> str:
    return digest_bytes(canonical_bytes(endpoint.semantic_frame.to_dict()))


def _fetch(
    reference: ExactBytesReference | RelationEvidenceReference,
    evidence: Mapping[str, bytes],
    upper: int,
) -> tuple[str, bytes | None]:
    try:
        payload = evidence[reference.digest]
    except (KeyError, TypeError):
        return "UNKNOWN", None
    if type(payload) is not bytes:
        return "INVALID", None
    if len(payload) > upper:
        return "UNKNOWN", None
    if len(payload) != reference.size_bytes or digest_bytes(payload) != reference.digest:
        return "INVALID", None
    return "BOUND", payload


def _topology_state(declaration: RelationBoundaryDeclaration) -> tuple[str, tuple[str, ...]]:
    preserved_sources = {item.source_facet for item in declaration.preservation_map}
    preserved_targets = {item.target_facet for item in declaration.preservation_map}
    consumed = set(declaration.consumed_facets)
    loss = set(declaration.loss_map)
    reasons: set[str] = set()
    if consumed != set(declaration.source.semantic_frame.facets):
        reasons.add("SOURCE_FACETS_NOT_FULLY_CONSUMED")
    if preserved_sources & loss or preserved_sources | loss != consumed:
        reasons.add("PRESERVATION_AND_LOSS_NOT_A_PARTITION")
    if preserved_targets != set(declaration.target.semantic_frame.facets):
        reasons.add("TARGET_FACETS_NOT_EXACTLY_PRODUCED")
    return ("VALID" if not reasons else "INVALID", tuple(sorted(reasons)))


def _frames_supported(declaration: RelationBoundaryDeclaration) -> bool:
    source = declaration.source.semantic_frame
    target = declaration.target.semantic_frame
    return (
        source.frame_id == target.frame_id == "CANONICAL-JSON-OBJECT-0.1"
        and source.proposition_language == target.proposition_language == "CANONICAL_JSON_OBJECT"
        and source.vocabulary_digest == target.vocabulary_digest
    )


def _decode_execution_evidence(data: bytes) -> dict[str, Any]:
    try:
        value = _object(
            _decode_canonical(data),
            {
                "checker_coordinate",
                "consumed_facets",
                "evidence_origin",
                "information_loss",
                "loss_map",
                "mechanism_id",
                "mechanism_profile_digest",
                "observations",
                "preservation_map",
                "producer_coordinate",
                "result",
                "schema_version",
                "source_digest",
                "source_frame_digest",
                "target_digest",
                "target_frame_digest",
                "translation_digest",
            },
            "relation execution evidence",
        )
        if value["schema_version"] != EVIDENCE_SCHEMA:
            raise RelationBoundaryError("unsupported relation evidence schema_version")
        if value["evidence_origin"] != "MECHANISM_EXECUTION":
            raise RelationBoundaryError("relation evidence must come from mechanism execution")
        for field in (
            "mechanism_profile_digest",
            "source_digest",
            "source_frame_digest",
            "target_digest",
            "target_frame_digest",
            "translation_digest",
        ):
            _digest(value[field])
        _checker_coordinate(value["checker_coordinate"])
        _text(value["mechanism_id"])
        _text(value["producer_coordinate"])
        _sorted_strings(value["consumed_facets"], allow_empty=False)
        _sorted_strings(value["loss_map"])
        _preservation_map(value["preservation_map"])
        if value["information_loss"] not in {"NONE", "PRESENT"}:
            raise RelationBoundaryError("unsupported information-loss state")
        if value["result"] not in {"ESTABLISHED", "REFUTED"}:
            raise RelationBoundaryError("evidence result must be established or refuted")
        observations = value["observations"]
        if type(observations) is not list or len(observations) > MAX_ITEMS:
            raise RelationBoundaryError("relation observations exceed their item bound")
        keys: list[tuple[str, str]] = []
        for raw in observations:
            observation = _object(
                raw,
                {
                    "equal",
                    "source_facet",
                    "source_value_digest",
                    "target_facet",
                    "target_value_digest",
                },
                "relation observation",
            )
            keys.append((_text(observation["source_facet"]), _text(observation["target_facet"])))
            _digest(observation["source_value_digest"])
            _digest(observation["target_value_digest"])
            if type(observation["equal"]) is not bool:
                raise RelationBoundaryError("relation equality observation must be Boolean")
        if keys != sorted(set(keys), key=lambda pair: (pair[0].encode("utf-8"), pair[1].encode("utf-8"))):
            raise RelationBoundaryError("relation observations must be unique and canonically ordered")
        return value
    except RelationBoundaryError:
        raise
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error


def expected_relation_boundary_evidence(
    declaration: RelationBoundaryDeclaration,
    source_bytes: bytes,
    target_bytes: bytes,
    producer_coordinate: str,
) -> bytes:
    """Replay the registered facet mapping and emit its expected evidence bytes."""

    try:
        _text(producer_coordinate)
        source = _decode_canonical(source_bytes, MAX_RELATION_ARTIFACT_BYTES)
        target = _decode_canonical(target_bytes, MAX_RELATION_ARTIFACT_BYTES)
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error
    observations = []
    all_equal = True
    for mapping in declaration.preservation_map:
        source_value = source[mapping.source_facet]
        target_value = target[mapping.target_facet]
        equal = canonical_bytes(source_value) == canonical_bytes(target_value)
        all_equal = all_equal and equal
        observations.append({
            "equal": equal,
            "source_facet": mapping.source_facet,
            "source_value_digest": digest_bytes(canonical_bytes(source_value)),
            "target_facet": mapping.target_facet,
            "target_value_digest": digest_bytes(canonical_bytes(target_value)),
        })
    return canonical_bytes({
        "checker_coordinate": declaration.translation.checker_coordinate.to_dict(),
        "consumed_facets": list(declaration.consumed_facets),
        "evidence_origin": "MECHANISM_EXECUTION",
        "information_loss": "PRESENT" if declaration.loss_map else "NONE",
        "loss_map": list(declaration.loss_map),
        "mechanism_id": declaration.translation.mechanism_id,
        "mechanism_profile_digest": declaration.translation.mechanism_profile_digest,
        "observations": observations,
        "preservation_map": [item.to_dict() for item in declaration.preservation_map],
        "producer_coordinate": producer_coordinate,
        "result": "ESTABLISHED" if all_equal else "REFUTED",
        "schema_version": EVIDENCE_SCHEMA,
        "source_digest": declaration.source.artifact.digest,
        "source_frame_digest": _frame_digest(declaration.source),
        "target_digest": declaration.target.artifact.digest,
        "target_frame_digest": _frame_digest(declaration.target),
        "translation_digest": _translation_digest(declaration),
    })


def qualify_relation_boundary(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> RelationBoundaryReceipt:
    """Recheck exact proposition bytes and evidence under the registered map."""

    declaration = decode_relation_boundary_declaration(declaration_bytes)
    declaration_digest = digest_bytes(declaration_bytes)
    checks: dict[str, str] = {
        "evidence_binding": "UNKNOWN",
        "evidence_recheck": "UNKNOWN",
        "frame_compatibility": "UNKNOWN",
        "mechanism_support": "UNKNOWN",
        "relation_evaluation": "UNKNOWN",
        "source_binding": "UNKNOWN",
        "target_binding": "UNKNOWN",
        "topology": "UNKNOWN",
    }
    reasons: set[str] = set()
    result = RelationResult.UNKNOWN
    references = (
        declaration.source.artifact.digest,
        declaration.target.artifact.digest,
        declaration.evidence.digest,
    )
    if (
        declaration_digest in references
        or declaration.evidence.digest
        in {declaration.source.artifact.digest, declaration.target.artifact.digest}
    ):
        reasons.add("CIRCULAR_OR_ALIASED_EVIDENCE_BINDING")
        result = RelationResult.INVALID

    source_state, source_bytes = _fetch(
        declaration.source.artifact, evidence, MAX_RELATION_ARTIFACT_BYTES
    )
    target_state, target_bytes = _fetch(
        declaration.target.artifact, evidence, MAX_RELATION_ARTIFACT_BYTES
    )
    evidence_state, evidence_bytes = _fetch(declaration.evidence, evidence, MAX_RECORD_BYTES)
    checks["source_binding"] = source_state
    checks["target_binding"] = target_state
    checks["evidence_binding"] = evidence_state
    for label, state in (
        ("SOURCE", source_state),
        ("TARGET", target_state),
        ("EXECUTION_EVIDENCE", evidence_state),
    ):
        if state != "BOUND":
            reasons.add(f"{label}_{state}")
            if state == "INVALID":
                result = RelationResult.INVALID

    topology, topology_reasons = _topology_state(declaration)
    checks["topology"] = topology
    reasons.update(topology_reasons)
    if topology == "INVALID":
        result = RelationResult.INVALID

    coordinate = current_checker_coordinate()
    supported = (
        declaration.translation.mechanism_id == MECHANISM_ID
        and declaration.translation.mechanism_profile_digest
        == relation_boundary_mechanism_profile_digest()
        and declaration.translation.checker_coordinate == coordinate
    )
    checks["mechanism_support"] = "SUPPORTED" if supported else "UNKNOWN"
    if not supported:
        reasons.add("MECHANISM_OR_PROFILE_UNSUPPORTED")
    frames_supported = _frames_supported(declaration)
    checks["frame_compatibility"] = "COMPATIBLE" if frames_supported else "UNKNOWN"
    if not frames_supported:
        reasons.add("SEMANTIC_FRAMES_INCOMPATIBLE")

    if (
        result is not RelationResult.INVALID
        and source_bytes is not None
        and target_bytes is not None
        and evidence_bytes is not None
    ):
        try:
            source = _decode_canonical(source_bytes, MAX_RELATION_ARTIFACT_BYTES)
            target = _decode_canonical(target_bytes, MAX_RELATION_ARTIFACT_BYTES)
            if tuple(sorted(source, key=lambda item: item.encode("utf-8"))) != declaration.source.semantic_frame.facets:
                raise RelationBoundaryError("source facets do not match the source frame")
            if tuple(sorted(target, key=lambda item: item.encode("utf-8"))) != declaration.target.semantic_frame.facets:
                raise RelationBoundaryError("target facets do not match the target frame")
            execution = _decode_execution_evidence(evidence_bytes)
            replay = expected_relation_boundary_evidence(
                declaration, source_bytes, target_bytes, execution["producer_coordinate"]
            )
            if replay != evidence_bytes:
                checks["evidence_recheck"] = "INVALID"
                reasons.add("EXECUTION_EVIDENCE_RECHECK_INVALID")
                result = RelationResult.INVALID
            elif supported and frames_supported and topology == "VALID":
                checks["evidence_recheck"] = "REPRODUCED"
                checks["relation_evaluation"] = execution["result"]
                result = RelationResult(execution["result"])
        except (RelationBoundaryError, SourceGroundingError, KeyError):
            checks["evidence_recheck"] = "INVALID"
            reasons.add("PROPOSITION_OR_EXECUTION_EVIDENCE_INVALID")
            result = RelationResult.INVALID

    return RelationBoundaryReceipt(
        declaration_digest,
        declaration.source.artifact.digest,
        declaration.target.artifact.digest,
        declaration.evidence.digest,
        declaration.translation.mechanism_profile_digest,
        coordinate,
        result,
        "PRESENT" if declaration.loss_map else "NONE",
        tuple(sorted(reasons)),
        tuple(sorted(checks.items())),
        declaration.consumed_facets,
        declaration.preservation_map,
        declaration.loss_map,
        declaration.assumptions,
    )


def build_relation_boundary_receipt(
    declaration_bytes: bytes, evidence: Mapping[str, bytes]
) -> bytes:
    """Build a deterministic unsigned receipt for the current relation replay."""

    return canonical_bytes(qualify_relation_boundary(declaration_bytes, evidence).to_dict())


def decode_relation_boundary_receipt(data: bytes) -> RelationBoundaryReceipt:
    """Decode receipt structure without accepting the recorded result as current."""

    try:
        value = _object(
            _decode_canonical(data),
            {
                "assumptions",
                "checker_coordinate",
                "checks",
                "consumed_facets",
                "declaration_digest",
                "evidence_digest",
                "information_loss",
                "loss_map",
                "mechanism_profile_digest",
                "preservation_map",
                "reason_codes",
                "residual_obligations",
                "result",
                "schema_version",
                "source_digest",
                "target_digest",
            },
            "relation boundary receipt",
        )
        if value["schema_version"] != RECEIPT_SCHEMA:
            raise RelationBoundaryError("unsupported relation boundary receipt schema_version")
        checks = value["checks"]
        expected_checks = {
            "evidence_binding",
            "evidence_recheck",
            "frame_compatibility",
            "mechanism_support",
            "relation_evaluation",
            "source_binding",
            "target_binding",
            "topology",
        }
        if type(checks) is not dict or set(checks) != expected_checks:
            raise RelationBoundaryError("receipt checks must have exactly their defined fields")
        check_items = tuple(sorted((_text(key), _text(item)) for key, item in checks.items()))
        preservation = _preservation_map(value["preservation_map"])
        loss = _sorted_strings(value["loss_map"])
        information_loss = value["information_loss"]
        if information_loss not in {"NONE", "PRESENT"}:
            raise RelationBoundaryError("unsupported information-loss state")
        if (information_loss == "PRESENT") != bool(loss):
            raise RelationBoundaryError("information-loss state does not match the loss map")
        residuals = _sorted_strings(value["residual_obligations"], allow_empty=False)
        if residuals != _RESIDUALS:
            raise RelationBoundaryError("relation residual obligations are not exact")
        try:
            result = RelationResult(value["result"])
        except (TypeError, ValueError) as error:
            raise RelationBoundaryError("unsupported relation boundary result") from error
        return RelationBoundaryReceipt(
            _digest(value["declaration_digest"]),
            _digest(value["source_digest"]),
            _digest(value["target_digest"]),
            _digest(value["evidence_digest"]),
            _digest(value["mechanism_profile_digest"]),
            _checker_coordinate(value["checker_coordinate"]),
            result,
            information_loss,
            _sorted_strings(value["reason_codes"]),
            check_items,
            _sorted_strings(value["consumed_facets"], allow_empty=False),
            preservation,
            loss,
            _sorted_strings(value["assumptions"]),
            residuals,
        )
    except RelationBoundaryError:
        raise
    except SourceGroundingError as error:
        raise RelationBoundaryError(str(error)) from error


def recheck_relation_boundary_receipt(
    declaration_bytes: bytes,
    receipt_bytes: bytes,
    evidence: Mapping[str, bytes],
) -> RelationBoundaryReceipt:
    """Require exact receipt reproduction from the current retained evidence."""

    decoded = decode_relation_boundary_receipt(receipt_bytes)
    rebuilt = build_relation_boundary_receipt(declaration_bytes, evidence)
    if rebuilt != receipt_bytes:
        raise RelationBoundaryError("RELATION_BOUNDARY_RECEIPT_NOT_REPRODUCED")
    return decoded
