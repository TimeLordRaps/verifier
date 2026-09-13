"""Experimental runtime-to-authority correspondence for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) records and Secure Hash Algorithm 256-bit
(SHA-256) digests bind retained authority-model, executable, deployment-artifact,
and event-trace bytes.  The bounded replay checks only observed transitions and
coverage of an explicit finite denominator.  It does not establish all runtime
behavior, actor identity, authorization, actual deployment, truth, or safety.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hmac
import json
from pathlib import Path
import re
from typing import Any

from .network import AUTHORITY_MODEL_SCHEMA, AuthorityModel, canonical_bytes, digest_bytes


DECLARATION_SCHEMA = "VSTD-RUNTIME-AUTHORITY-CORRESPONDENCE-0.1"
TRACE_SCHEMA = "VSTD-RUNTIME-AUTHORITY-TRACE-0.1"
RECEIPT_SCHEMA = "VSTD-RUNTIME-AUTHORITY-CORRESPONDENCE-RECEIPT-0.1"
PROFILE_SCHEMA = "VSTD-RUNTIME-AUTHORITY-CORRESPONDENCE-PROFILE-0.1"
SUPPORTED_RUNTIME_KIND = "VSTD-RETAINED-EVENT-TRACE-REPLAY-0.1"

MAX_DECLARATION_BYTES = 262_144
MAX_MODEL_BYTES = 1_048_576
MAX_EXECUTABLE_BYTES = 1_048_576
MAX_DEPLOYED_ARTIFACT_BYTES = 1_048_576
MAX_TRACE_BYTES = 1_048_576
MAX_DERIVER_DECLARATION_BYTES = 131_072
MAX_DERIVER_RECEIPT_BYTES = 2_228_224
MAX_TOTAL_EVIDENCE_BYTES = 8_388_608
MAX_RECEIPT_BYTES = 12_582_912
MAX_SELECTED_EVIDENCE_ENTRIES = 6
MAX_EVENTS = 1_024
MAX_STATES = 256
MAX_TRANSITIONS = 256
MAX_JSON_DEPTH = 20
MAX_JSON_CONTAINERS = 16_384
MAX_JSON_NODES = 32_768
MAX_TEXT = 256

CLAIM_BOUNDARY = (
    "This receipt requires an independently reproduced bounded deriver execution whose "
    "exact standard-output bytes are the retained trace, then deterministically replays "
    "only those recorded events against one exact authority model and finite coverage "
    "denominator. It does not prove unobserved runtime behavior, actor identity, "
    "authorization, sandboxing, secrecy, actual deployment, deployment continuity, "
    "artifact truth, correctness, safety, or another runtime coordinate."
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_BYTES = canonical_bytes(
    {
        "schema_version": PROFILE_SCHEMA,
        "declaration_schema": DECLARATION_SCHEMA,
        "trace_schema": TRACE_SCHEMA,
        "receipt_schema": RECEIPT_SCHEMA,
        "supported_runtime_kind": SUPPORTED_RUNTIME_KIND,
        "rules": [
            "bind_exact_retained_authority_model_executable_deployment_and_trace_bytes",
            "independently_recheck_one_bound_deriver_execution_receipt",
            "require_reproduced_standard_output_to_equal_the_exact_trace_bytes",
            "require_one_to_one_event_signature_to_authority_transition_mapping",
            "reconstruct_state_from_a_declared_initial_state_and_contiguous_event_sequence",
            "distinguish_observed_transition_correspondence_from_finite_coverage_completeness",
            "preserve_refuted_unknown_and_invalid_outcomes",
        ],
        "limits": {
            "max_declaration_bytes": MAX_DECLARATION_BYTES,
            "max_model_bytes": MAX_MODEL_BYTES,
            "max_executable_bytes": MAX_EXECUTABLE_BYTES,
            "max_deployed_artifact_bytes": MAX_DEPLOYED_ARTIFACT_BYTES,
            "max_trace_bytes": MAX_TRACE_BYTES,
            "max_deriver_declaration_bytes": MAX_DERIVER_DECLARATION_BYTES,
            "max_deriver_receipt_bytes": MAX_DERIVER_RECEIPT_BYTES,
            "max_total_evidence_bytes": MAX_TOTAL_EVIDENCE_BYTES,
            "max_events": MAX_EVENTS,
            "max_states": MAX_STATES,
            "max_transitions": MAX_TRANSITIONS,
            "max_json_depth": MAX_JSON_DEPTH,
            "max_json_containers": MAX_JSON_CONTAINERS,
            "max_json_nodes": MAX_JSON_NODES,
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
)


class RuntimeAuthorityError(ValueError):
    """Base class for bounded runtime-authority record defects."""


class RuntimeAuthorityInvalid(RuntimeAuthorityError):
    """The supplied data is malformed, inconsistent, or substituted."""


class RuntimeAuthorityUnsupported(RuntimeAuthorityError):
    """The supplied data uses an unsupported interpretation."""


class RuntimeAuthorityLimit(RuntimeAuthorityError):
    """The bounded checker cannot complete within its declared limits."""


class CorrespondenceVerdict(str, Enum):
    """Four-way outcome for byte binding or observed-transition correspondence."""

    ESTABLISHED = "ESTABLISHED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


class CoverageCompleteness(str, Enum):
    """Coverage outcome relative only to the declared finite denominator."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


def runtime_authority_profile_bytes() -> bytes:
    """Return inert mechanism-profile bytes; no supplied code is loaded."""

    return _PROFILE_BYTES


def runtime_authority_profile_digest() -> str:
    """Identify the exact experimental rule declaration."""

    return digest_bytes(_PROFILE_BYTES)


def _strict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise RuntimeAuthorityInvalid(f"{label} fields are not exact")
    return value


def _text(value: Any, label: str, maximum: int = MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    ):
        raise RuntimeAuthorityInvalid(f"{label} must be bounded nonempty text")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RuntimeAuthorityInvalid(f"{label} must be a canonical SHA-256 digest")
    return value


def _bounded_positive_integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or value < 1:
        raise RuntimeAuthorityInvalid(f"{label} must be a positive integer")
    if value > maximum:
        raise RuntimeAuthorityLimit(f"{label} exceeds the mechanism limit")
    return value


def _decode_canonical(data: bytes, schema: str, maximum: int) -> dict[str, Any]:
    if type(data) is not bytes:
        raise RuntimeAuthorityUnsupported("ordinary immutable bytes are required")
    if len(data) > maximum:
        raise RuntimeAuthorityLimit("record byte limit exceeded")
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
            if depth > MAX_JSON_DEPTH or containers > MAX_JSON_CONTAINERS:
                raise RuntimeAuthorityLimit("record syntax limit exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise RuntimeAuthorityInvalid("unbalanced record")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RuntimeAuthorityInvalid("duplicate record field")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(RuntimeAuthorityInvalid("floating-point value")),
            parse_constant=lambda _value: (_ for _ in ()).throw(RuntimeAuthorityInvalid("non-finite value")),
        )
        if type(value) is not dict or canonical_bytes(value) != data:
            raise RuntimeAuthorityInvalid("record is not canonical")
    except RuntimeAuthorityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RuntimeAuthorityInvalid("record cannot be decoded") from exc
    discriminator = value.get("schema_version")
    if type(discriminator) is not str:
        raise RuntimeAuthorityInvalid("record lacks a schema discriminator")
    if discriminator != schema:
        raise RuntimeAuthorityUnsupported("unsupported schema discriminator")
    stack: list[Any] = [value]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise RuntimeAuthorityLimit("decoded record node limit exceeded")
        if type(item) is dict:
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    return value


@dataclass(frozen=True)
class RuntimeCoordinate:
    """Bounded declared runtime coordinate; it is not proof of deployment."""

    runtime_kind: str
    platform: str
    runtime_version: str
    invocation_digest: str
    execution_coordinate_digest: str
    deployment_coordinate: str
    maximum_events: int

    def __post_init__(self) -> None:
        _text(self.runtime_kind, "runtime kind")
        _text(self.platform, "platform")
        _text(self.runtime_version, "runtime version")
        _digest(self.invocation_digest, "invocation digest")
        _digest(self.execution_coordinate_digest, "execution coordinate digest")
        _text(self.deployment_coordinate, "deployment coordinate")
        _bounded_positive_integer(self.maximum_events, "maximum events", MAX_EVENTS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_kind": self.runtime_kind,
            "platform": self.platform,
            "runtime_version": self.runtime_version,
            "invocation_digest": self.invocation_digest,
            "execution_coordinate_digest": self.execution_coordinate_digest,
            "deployment_coordinate": self.deployment_coordinate,
            "maximum_events": self.maximum_events,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeCoordinate":
        value = _strict(
            value,
            {
                "runtime_kind",
                "platform",
                "runtime_version",
                "invocation_digest",
                "execution_coordinate_digest",
                "deployment_coordinate",
                "maximum_events",
            },
            "runtime coordinate",
        )
        return cls(**value)

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class TransitionMapping:
    """One exact event signature mapped to one declared authority transition."""

    event_type: str
    actor_scope: str
    action: str
    authority_transition_id: str

    def __post_init__(self) -> None:
        _text(self.event_type, "event type")
        _text(self.actor_scope, "actor scope")
        _text(self.action, "action")
        _text(self.authority_transition_id, "authority transition identifier")

    @property
    def event_signature(self) -> tuple[str, str, str]:
        return self.event_type, self.actor_scope, self.action

    def to_dict(self) -> dict[str, str]:
        return {
            "event_type": self.event_type,
            "actor_scope": self.actor_scope,
            "action": self.action,
            "authority_transition_id": self.authority_transition_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "TransitionMapping":
        return cls(**_strict(value, {"event_type", "actor_scope", "action", "authority_transition_id"}, "transition mapping"))


@dataclass(frozen=True)
class RuntimeAuthorityDeclaration:
    """Exact coordinates and finite denominator for one replay assessment."""

    profile_digest: str
    authority_model_digest: str
    executable_artifact_digest: str
    deployed_artifact_digest: str
    trace_digest: str
    deriver_declaration_digest: str
    deriver_receipt_digest: str
    deriver_checker_source_digest: str
    deriver_standard_output_digest: str
    deriver_standard_output_size_bytes: int
    runtime_coordinate: RuntimeCoordinate
    initial_state_id: str
    transition_mappings: tuple[TransitionMapping, ...]
    coverage_transition_ids: tuple[str, ...]
    schema_version: str = DECLARATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != DECLARATION_SCHEMA:
            raise RuntimeAuthorityUnsupported("unsupported declaration schema")
        _digest(self.profile_digest, "profile digest")
        _digest(self.authority_model_digest, "authority model digest")
        _digest(self.executable_artifact_digest, "executable artifact digest")
        _digest(self.deployed_artifact_digest, "deployed artifact digest")
        _digest(self.trace_digest, "trace digest")
        _digest(self.deriver_declaration_digest, "deriver declaration digest")
        _digest(self.deriver_receipt_digest, "deriver receipt digest")
        _digest(self.deriver_checker_source_digest, "deriver checker source digest")
        _digest(self.deriver_standard_output_digest, "deriver standard-output digest")
        _bounded_positive_integer(
            self.deriver_standard_output_size_bytes,
            "deriver standard-output size",
            MAX_TRACE_BYTES,
        )
        if not isinstance(self.runtime_coordinate, RuntimeCoordinate):
            raise RuntimeAuthorityInvalid("runtime coordinate must be typed")
        _text(self.initial_state_id, "initial state identifier")
        if not self.transition_mappings:
            raise RuntimeAuthorityInvalid("at least one transition mapping is required")
        if len(self.transition_mappings) > MAX_TRANSITIONS:
            raise RuntimeAuthorityLimit("transition mapping limit exceeded")
        if not all(isinstance(item, TransitionMapping) for item in self.transition_mappings):
            raise RuntimeAuthorityInvalid("transition mappings must be typed")
        ordered = tuple(sorted(self.transition_mappings, key=lambda item: (*item.event_signature, item.authority_transition_id)))
        if self.transition_mappings != ordered:
            raise RuntimeAuthorityInvalid("transition mappings must be canonically ordered")
        signatures = [item.event_signature for item in self.transition_mappings]
        transition_ids = [item.authority_transition_id for item in self.transition_mappings]
        if len(signatures) != len(set(signatures)) or len(transition_ids) != len(set(transition_ids)):
            raise RuntimeAuthorityInvalid("transition mapping alias is not allowed")
        coverage = tuple(_text(item, "coverage transition identifier") for item in self.coverage_transition_ids)
        if not coverage or coverage != tuple(sorted(set(coverage))):
            raise RuntimeAuthorityInvalid("coverage denominator must be nonempty, sorted, and unique")
        if len(coverage) > MAX_TRANSITIONS:
            raise RuntimeAuthorityLimit("coverage denominator limit exceeded")
        if set(coverage) != set(transition_ids):
            raise RuntimeAuthorityInvalid("every denominator transition requires exactly one mapping")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_digest": self.profile_digest,
            "authority_model_digest": self.authority_model_digest,
            "executable_artifact_digest": self.executable_artifact_digest,
            "deployed_artifact_digest": self.deployed_artifact_digest,
            "trace_digest": self.trace_digest,
            "deriver_declaration_digest": self.deriver_declaration_digest,
            "deriver_receipt_digest": self.deriver_receipt_digest,
            "deriver_checker_source_digest": self.deriver_checker_source_digest,
            "deriver_standard_output_digest": self.deriver_standard_output_digest,
            "deriver_standard_output_size_bytes": self.deriver_standard_output_size_bytes,
            "runtime_coordinate": self.runtime_coordinate.to_dict(),
            "initial_state_id": self.initial_state_id,
            "transition_mappings": [item.to_dict() for item in self.transition_mappings],
            "coverage_transition_ids": list(self.coverage_transition_ids),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeAuthorityDeclaration":
        value = _strict(
            value,
            {
                "schema_version",
                "profile_digest",
                "authority_model_digest",
                "executable_artifact_digest",
                "deployed_artifact_digest",
                "trace_digest",
                "deriver_declaration_digest",
                "deriver_receipt_digest",
                "deriver_checker_source_digest",
                "deriver_standard_output_digest",
                "deriver_standard_output_size_bytes",
                "runtime_coordinate",
                "initial_state_id",
                "transition_mappings",
                "coverage_transition_ids",
            },
            "runtime-authority declaration",
        )
        mappings = value["transition_mappings"]
        coverage = value["coverage_transition_ids"]
        if type(mappings) is not list or type(coverage) is not list:
            raise RuntimeAuthorityInvalid("mapping and coverage fields must be arrays")
        return cls(
            schema_version=value["schema_version"],
            profile_digest=value["profile_digest"],
            authority_model_digest=value["authority_model_digest"],
            executable_artifact_digest=value["executable_artifact_digest"],
            deployed_artifact_digest=value["deployed_artifact_digest"],
            trace_digest=value["trace_digest"],
            deriver_declaration_digest=value["deriver_declaration_digest"],
            deriver_receipt_digest=value["deriver_receipt_digest"],
            deriver_checker_source_digest=value["deriver_checker_source_digest"],
            deriver_standard_output_digest=value["deriver_standard_output_digest"],
            deriver_standard_output_size_bytes=value["deriver_standard_output_size_bytes"],
            runtime_coordinate=RuntimeCoordinate.from_dict(value["runtime_coordinate"]),
            initial_state_id=value["initial_state_id"],
            transition_mappings=tuple(TransitionMapping.from_dict(item) for item in mappings),
            coverage_transition_ids=tuple(coverage),
        )


@dataclass(frozen=True)
class TraceEvent:
    """One retained event in an explicitly ordered observation trace."""

    sequence: int
    event_id: str
    event_type: str
    actor_scope: str
    action: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise RuntimeAuthorityInvalid("event sequence must be a nonnegative integer")
        _text(self.event_id, "event identifier")
        _text(self.event_type, "event type")
        _text(self.actor_scope, "event actor scope")
        _text(self.action, "event action")

    @property
    def event_signature(self) -> tuple[str, str, str]:
        return self.event_type, self.actor_scope, self.action

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "actor_scope": self.actor_scope,
            "action": self.action,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "TraceEvent":
        return cls(**_strict(value, {"sequence", "event_id", "event_type", "actor_scope", "action"}, "trace event"))


@dataclass(frozen=True)
class RuntimeTrace:
    """Retained events bound to the model, artifacts, and runtime coordinate."""

    authority_model_digest: str
    executable_artifact_digest: str
    deployed_artifact_digest: str
    runtime_coordinate_digest: str
    events: tuple[TraceEvent, ...]
    schema_version: str = TRACE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != TRACE_SCHEMA:
            raise RuntimeAuthorityUnsupported("unsupported trace schema")
        _digest(self.authority_model_digest, "trace authority model digest")
        _digest(self.executable_artifact_digest, "trace executable artifact digest")
        _digest(self.deployed_artifact_digest, "trace deployed artifact digest")
        _digest(self.runtime_coordinate_digest, "trace runtime coordinate digest")
        if not self.events:
            raise RuntimeAuthorityInvalid("trace must retain at least one event")
        if len(self.events) > MAX_EVENTS:
            raise RuntimeAuthorityLimit("event count limit exceeded")
        if not all(isinstance(item, TraceEvent) for item in self.events):
            raise RuntimeAuthorityInvalid("trace events must be typed")
        if tuple(item.sequence for item in self.events) != tuple(range(len(self.events))):
            raise RuntimeAuthorityInvalid("trace sequence has a gap or reordering")
        event_ids = [item.event_id for item in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise RuntimeAuthorityInvalid("trace event identifiers must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_model_digest": self.authority_model_digest,
            "executable_artifact_digest": self.executable_artifact_digest,
            "deployed_artifact_digest": self.deployed_artifact_digest,
            "runtime_coordinate_digest": self.runtime_coordinate_digest,
            "events": [item.to_dict() for item in self.events],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeTrace":
        value = _strict(
            value,
            {
                "schema_version",
                "authority_model_digest",
                "executable_artifact_digest",
                "deployed_artifact_digest",
                "runtime_coordinate_digest",
                "events",
            },
            "runtime trace",
        )
        if type(value["events"]) is not list:
            raise RuntimeAuthorityInvalid("trace events must be an array")
        return cls(
            schema_version=value["schema_version"],
            authority_model_digest=value["authority_model_digest"],
            executable_artifact_digest=value["executable_artifact_digest"],
            deployed_artifact_digest=value["deployed_artifact_digest"],
            runtime_coordinate_digest=value["runtime_coordinate_digest"],
            events=tuple(TraceEvent.from_dict(item) for item in value["events"]),
        )


@dataclass(frozen=True)
class RetainedEvidence:
    """One exact evidence payload retained inside a portable receipt."""

    coordinate: str
    payload_base64: str

    def __post_init__(self) -> None:
        _digest(self.coordinate, "retained evidence coordinate")
        _decode_base64(self.payload_base64)

    def to_dict(self) -> dict[str, str]:
        return {"coordinate": self.coordinate, "payload_base64": self.payload_base64}

    @classmethod
    def from_bytes(cls, coordinate: str, payload: bytes) -> "RetainedEvidence":
        return cls(coordinate, base64.b64encode(payload).decode("ascii"))

    def payload(self) -> bytes:
        return _decode_base64(self.payload_base64)


def _decode_base64(value: Any) -> bytes:
    if type(value) is not str:
        raise RuntimeAuthorityInvalid("retained payload must be base64 text")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeAuthorityInvalid("retained payload is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimeAuthorityInvalid("retained payload is not canonical base64")
    return decoded


@dataclass(frozen=True)
class RuntimeAuthorityReceipt:
    """Portable receipt whose retained evidence can be independently replayed."""

    declaration_base64: str
    declaration_digest: str
    profile_digest: str
    runtime_coordinate_digest: str | None
    retained_evidence: tuple[RetainedEvidence, ...]
    coordinate_binding: CorrespondenceVerdict
    observed_transition_correspondence: CorrespondenceVerdict
    coverage_completeness: CoverageCompleteness
    observed_event_count: int | None
    covered_transition_ids: tuple[str, ...]
    reconstructed_state_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    claim_boundary: str
    receipt_digest: str | None = None
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise RuntimeAuthorityUnsupported("unsupported receipt schema")
        _decode_base64(self.declaration_base64)
        _digest(self.declaration_digest, "declaration digest")
        _digest(self.profile_digest, "receipt profile digest")
        if self.runtime_coordinate_digest is not None:
            _digest(self.runtime_coordinate_digest, "runtime coordinate digest")
        if not all(isinstance(item, RetainedEvidence) for item in self.retained_evidence):
            raise RuntimeAuthorityInvalid("retained evidence must be typed")
        if len(self.retained_evidence) > MAX_SELECTED_EVIDENCE_ENTRIES:
            raise RuntimeAuthorityLimit("retained evidence entry limit exceeded")
        if sum(len(item.payload()) for item in self.retained_evidence) > MAX_TOTAL_EVIDENCE_BYTES:
            raise RuntimeAuthorityLimit("retained evidence byte limit exceeded")
        coordinates = [item.coordinate for item in self.retained_evidence]
        if coordinates != sorted(set(coordinates)):
            raise RuntimeAuthorityInvalid("retained evidence coordinates must be sorted and unique")
        if not isinstance(self.coordinate_binding, CorrespondenceVerdict) or not isinstance(
            self.observed_transition_correspondence, CorrespondenceVerdict
        ) or not isinstance(self.coverage_completeness, CoverageCompleteness):
            raise RuntimeAuthorityInvalid("receipt verdicts must be typed")
        if self.observed_event_count is not None and (type(self.observed_event_count) is not int or self.observed_event_count < 0):
            raise RuntimeAuthorityInvalid("observed event count is invalid")
        if self.covered_transition_ids != tuple(sorted(set(self.covered_transition_ids))):
            raise RuntimeAuthorityInvalid("covered transition identifiers must be sorted and unique")
        if any(type(item) is not str for item in self.reconstructed_state_ids):
            raise RuntimeAuthorityInvalid("reconstructed state identifiers must be text")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise RuntimeAuthorityInvalid("reason codes must be sorted and unique")
        if self.claim_boundary != CLAIM_BOUNDARY:
            raise RuntimeAuthorityInvalid("claim boundary was substituted")
        if self.receipt_digest is not None:
            _digest(self.receipt_digest, "receipt digest")

    def body_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "declaration_base64": self.declaration_base64,
            "declaration_digest": self.declaration_digest,
            "profile_digest": self.profile_digest,
            "runtime_coordinate_digest": self.runtime_coordinate_digest,
            "retained_evidence": [item.to_dict() for item in self.retained_evidence],
            "coordinate_binding": self.coordinate_binding.value,
            "observed_transition_correspondence": self.observed_transition_correspondence.value,
            "coverage_completeness": self.coverage_completeness.value,
            "observed_event_count": self.observed_event_count,
            "covered_transition_ids": list(self.covered_transition_ids),
            "reconstructed_state_ids": list(self.reconstructed_state_ids),
            "reason_codes": list(self.reason_codes),
            "claim_boundary": self.claim_boundary,
        }

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.body_dict()))

    def to_dict(self) -> dict[str, Any]:
        value = self.body_dict()
        value["receipt_digest"] = self.receipt_digest or self.canonical_digest()
        return value

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeAuthorityReceipt":
        value = _strict(
            value,
            {
                "schema_version",
                "declaration_base64",
                "declaration_digest",
                "profile_digest",
                "runtime_coordinate_digest",
                "retained_evidence",
                "coordinate_binding",
                "observed_transition_correspondence",
                "coverage_completeness",
                "observed_event_count",
                "covered_transition_ids",
                "reconstructed_state_ids",
                "reason_codes",
                "claim_boundary",
                "receipt_digest",
            },
            "runtime-authority receipt",
        )
        arrays = ("retained_evidence", "covered_transition_ids", "reconstructed_state_ids", "reason_codes")
        if any(type(value[field]) is not list for field in arrays):
            raise RuntimeAuthorityInvalid("receipt collection fields must be arrays")
        return cls(
            schema_version=value["schema_version"],
            declaration_base64=value["declaration_base64"],
            declaration_digest=value["declaration_digest"],
            profile_digest=value["profile_digest"],
            runtime_coordinate_digest=value["runtime_coordinate_digest"],
            retained_evidence=tuple(
                RetainedEvidence(**_strict(item, {"coordinate", "payload_base64"}, "retained evidence"))
                for item in value["retained_evidence"]
            ),
            coordinate_binding=CorrespondenceVerdict(value["coordinate_binding"]),
            observed_transition_correspondence=CorrespondenceVerdict(value["observed_transition_correspondence"]),
            coverage_completeness=CoverageCompleteness(value["coverage_completeness"]),
            observed_event_count=value["observed_event_count"],
            covered_transition_ids=tuple(value["covered_transition_ids"]),
            reconstructed_state_ids=tuple(value["reconstructed_state_ids"]),
            reason_codes=tuple(value["reason_codes"]),
            claim_boundary=value["claim_boundary"],
            receipt_digest=value["receipt_digest"],
        )


@dataclass(frozen=True)
class ReceiptRecheck:
    """Independent receipt-integrity and deterministic-replay result."""

    verdict: CorrespondenceVerdict
    reason_codes: tuple[str, ...]
    receipt_digest: str | None


@dataclass(frozen=True)
class DeriverExecutionEvidence:
    """Normalized result of the independently implemented deriver rechecker."""

    status: CorrespondenceVerdict
    standard_output_bytes: bytes | None
    executable_digest: str | None
    runtime_coordinate_digest: str | None
    checker_source_digest: str | None
    reason_codes: tuple[str, ...]


def _recheck_deriver_execution(
    declaration_bytes: bytes,
    receipt_bytes: bytes,
    executable_path: str | Path | None,
) -> DeriverExecutionEvidence:
    """Lazily invoke the independent bounded-execution implementation."""

    try:
        from .deriver_self_status import (
            DeriverSelfStatus,
            DeriverSessionDeclaration,
            DeriverSessionReceipt,
            recheck_deriver_self_status,
        )
    except (ImportError, ModuleNotFoundError):
        return DeriverExecutionEvidence(
            CorrespondenceVerdict.UNKNOWN,
            None,
            None,
            None,
            None,
            ("DERIVER_SELF_STATUS_IMPLEMENTATION_UNAVAILABLE",),
        )
    try:
        declaration = DeriverSessionDeclaration.from_bytes(declaration_bytes)
        receipt = DeriverSessionReceipt.from_bytes(receipt_bytes)
        assessment = recheck_deriver_self_status(
            declaration_bytes,
            receipt_bytes,
            executable_path,
        )
        status = CorrespondenceVerdict(assessment.status.value)
        if assessment.declaration_digest != digest_bytes(declaration_bytes):
            status = CorrespondenceVerdict.INVALID
        if assessment.receipt_digest != digest_bytes(receipt_bytes):
            status = CorrespondenceVerdict.INVALID
        stdout = receipt.stdout_bytes if status is CorrespondenceVerdict.ESTABLISHED else None
        return DeriverExecutionEvidence(
            status,
            stdout,
            declaration.runtime_coordinate.executable_digest,
            digest_bytes(canonical_bytes(declaration.runtime_coordinate.to_dict())),
            assessment.checker_source_digest,
            tuple(assessment.reason_codes),
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return DeriverExecutionEvidence(
            CorrespondenceVerdict.INVALID,
            None,
            None,
            None,
            None,
            ("DERIVER_EXECUTION_EVIDENCE_INVALID",),
        )


def _load_selected_evidence(
    evidence: dict[str, bytes], coordinates: tuple[str, ...]
) -> tuple[dict[str, bytes | None], tuple[RetainedEvidence, ...]]:
    if type(evidence) is not dict:
        raise RuntimeAuthorityUnsupported("ordinary evidence dictionary required")
    selected: dict[str, bytes | None] = {}
    retained: list[RetainedEvidence] = []
    total = 0
    for coordinate in sorted(set(coordinates)):
        value = evidence.get(coordinate)
        if type(value) is not bytes:
            selected[coordinate] = None
            continue
        total += len(value)
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RuntimeAuthorityLimit("total selected evidence byte limit exceeded")
        selected[coordinate] = value
        retained.append(RetainedEvidence.from_bytes(coordinate, value))
    return selected, tuple(retained)


def _payload(selected: dict[str, bytes | None], coordinate: str, maximum: int) -> bytes:
    if coordinate not in selected or selected[coordinate] is None:
        raise RuntimeAuthorityUnsupported("selected evidence is missing or untrusted")
    payload = selected[coordinate]
    assert isinstance(payload, bytes)
    if len(payload) > maximum:
        raise RuntimeAuthorityLimit("selected evidence byte limit exceeded")
    if not hmac.compare_digest(digest_bytes(payload), coordinate):
        raise RuntimeAuthorityInvalid("selected evidence digest substitution")
    return payload


def _model(payload: bytes) -> AuthorityModel:
    value = _decode_canonical(payload, AUTHORITY_MODEL_SCHEMA, MAX_MODEL_BYTES)
    try:
        model = AuthorityModel.from_dict(value)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeAuthorityInvalid("authority model is malformed") from exc
    states = {item.state_id for item in model.states}
    transitions = {item.transition_id for item in model.transitions}
    if (
        len(states) > MAX_STATES
        or len(transitions) > MAX_TRANSITIONS
        or set(model.state_universe) != states
        or set(model.transition_universe) != transitions
        or not model.initial_state_ids
        or not set(model.initial_state_ids) <= states
        or any(item.source_state_id not in states or item.target_state_id not in states for item in model.transitions)
    ):
        raise RuntimeAuthorityInvalid("authority model topology is invalid")
    return model


def _trace(payload: bytes) -> RuntimeTrace:
    return RuntimeTrace.from_dict(_decode_canonical(payload, TRACE_SCHEMA, MAX_TRACE_BYTES))


def _new_receipt(
    declaration_bytes: bytes,
    retained: tuple[RetainedEvidence, ...],
    *,
    runtime_coordinate_digest: str | None = None,
    coordinate_binding: CorrespondenceVerdict = CorrespondenceVerdict.UNKNOWN,
    correspondence: CorrespondenceVerdict = CorrespondenceVerdict.UNKNOWN,
    coverage: CoverageCompleteness = CoverageCompleteness.UNKNOWN,
    event_count: int | None = None,
    covered: tuple[str, ...] = (),
    states: tuple[str, ...] = (),
    reasons: tuple[str, ...] = (),
) -> RuntimeAuthorityReceipt:
    receipt = RuntimeAuthorityReceipt(
        declaration_base64=base64.b64encode(declaration_bytes).decode("ascii"),
        declaration_digest=digest_bytes(declaration_bytes),
        profile_digest=runtime_authority_profile_digest(),
        runtime_coordinate_digest=runtime_coordinate_digest,
        retained_evidence=retained,
        coordinate_binding=coordinate_binding,
        observed_transition_correspondence=correspondence,
        coverage_completeness=coverage,
        observed_event_count=event_count,
        covered_transition_ids=tuple(sorted(set(covered))),
        reconstructed_state_ids=states,
        reason_codes=tuple(sorted(set(reasons))),
        claim_boundary=CLAIM_BOUNDARY,
    )
    return RuntimeAuthorityReceipt(**{**receipt.__dict__, "receipt_digest": receipt.canonical_digest()})


def build_runtime_authority_correspondence_receipt(
    declaration_bytes: bytes,
    evidence: dict[str, bytes],
    deriver_executable_path: str | Path | None = None,
) -> RuntimeAuthorityReceipt:
    """Bind and replay one retained trace without widening its claim surface."""

    if type(declaration_bytes) is not bytes:
        raise RuntimeAuthorityUnsupported("declaration requires ordinary immutable bytes")
    if len(declaration_bytes) > MAX_DECLARATION_BYTES:
        raise RuntimeAuthorityLimit("declaration byte limit exceeded")
    retained: tuple[RetainedEvidence, ...] = ()
    try:
        declaration = RuntimeAuthorityDeclaration.from_dict(
            _decode_canonical(declaration_bytes, DECLARATION_SCHEMA, MAX_DECLARATION_BYTES)
        )
    except RuntimeAuthorityUnsupported:
        return _new_receipt(declaration_bytes, retained, reasons=("DECLARATION_UNSUPPORTED",))
    except RuntimeAuthorityLimit:
        return _new_receipt(declaration_bytes, retained, reasons=("DECLARATION_LIMIT_EXHAUSTED",))
    except (RuntimeAuthorityInvalid, ValueError, TypeError, KeyError, AttributeError):
        return _new_receipt(
            declaration_bytes,
            retained,
            coordinate_binding=CorrespondenceVerdict.INVALID,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=("DECLARATION_INVALID",),
        )

    runtime_digest = declaration.runtime_coordinate.canonical_digest()
    coordinates = (
        declaration.authority_model_digest,
        declaration.executable_artifact_digest,
        declaration.deployed_artifact_digest,
        declaration.trace_digest,
        declaration.deriver_declaration_digest,
        declaration.deriver_receipt_digest,
    )
    try:
        selected, retained = _load_selected_evidence(evidence, coordinates)
    except RuntimeAuthorityUnsupported:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            reasons=("EVIDENCE_UNTRUSTED_OR_MISSING",),
        )
    except RuntimeAuthorityLimit:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            reasons=("EVIDENCE_LIMIT_EXHAUSTED",),
        )

    try:
        model_payload = _payload(selected, declaration.authority_model_digest, MAX_MODEL_BYTES)
        _payload(selected, declaration.executable_artifact_digest, MAX_EXECUTABLE_BYTES)
        _payload(selected, declaration.deployed_artifact_digest, MAX_DEPLOYED_ARTIFACT_BYTES)
        trace_payload = _payload(selected, declaration.trace_digest, MAX_TRACE_BYTES)
        deriver_declaration_payload = _payload(
            selected,
            declaration.deriver_declaration_digest,
            MAX_DERIVER_DECLARATION_BYTES,
        )
        deriver_receipt_payload = _payload(
            selected,
            declaration.deriver_receipt_digest,
            MAX_DERIVER_RECEIPT_BYTES,
        )
    except RuntimeAuthorityUnsupported:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            reasons=("SELECTED_EVIDENCE_MISSING_OR_UNTRUSTED",),
        )
    except RuntimeAuthorityLimit:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            reasons=("SELECTED_EVIDENCE_LIMIT_EXHAUSTED",),
        )
    except RuntimeAuthorityInvalid:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=CorrespondenceVerdict.INVALID,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=("SELECTED_EVIDENCE_SUBSTITUTED",),
        )

    coordinate_binding = CorrespondenceVerdict.ESTABLISHED
    if declaration.profile_digest != runtime_authority_profile_digest():
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            reasons=("PROFILE_UNSUPPORTED",),
        )
    if declaration.runtime_coordinate.runtime_kind != SUPPORTED_RUNTIME_KIND:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            reasons=("RUNTIME_KIND_UNSUPPORTED",),
        )

    if (
        declaration.deriver_standard_output_digest != declaration.trace_digest
        or declaration.deriver_standard_output_size_bytes != len(trace_payload)
    ):
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=("DERIVER_OUTPUT_TRACE_DECLARATION_INVALID",),
        )
    deriver = _recheck_deriver_execution(
        deriver_declaration_payload,
        deriver_receipt_payload,
        deriver_executable_path,
    )
    if deriver.status is CorrespondenceVerdict.UNKNOWN:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            reasons=tuple(deriver.reason_codes) + ("DERIVER_EXECUTION_NOT_ESTABLISHED",),
        )
    if deriver.status is CorrespondenceVerdict.REFUTED:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.REFUTED,
            reasons=tuple(deriver.reason_codes) + ("DERIVER_EXECUTION_REFUTED",),
        )
    if deriver.status is CorrespondenceVerdict.INVALID:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=tuple(deriver.reason_codes) + ("DERIVER_EXECUTION_INVALID",),
        )
    if (
        deriver.standard_output_bytes != trace_payload
        or deriver.executable_digest != declaration.executable_artifact_digest
        or deriver.runtime_coordinate_digest
        != declaration.runtime_coordinate.execution_coordinate_digest
        or deriver.checker_source_digest != declaration.deriver_checker_source_digest
    ):
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=("DERIVER_EXECUTION_TRACE_OR_COORDINATE_MISMATCH",),
        )

    try:
        model = _model(model_payload)
        trace = _trace(trace_payload)
    except RuntimeAuthorityUnsupported:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            reasons=("MODEL_OR_TRACE_UNSUPPORTED",),
        )
    except RuntimeAuthorityLimit:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            reasons=("MODEL_OR_TRACE_LIMIT_EXHAUSTED",),
        )
    except (RuntimeAuthorityInvalid, ValueError, TypeError, KeyError, AttributeError):
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            reasons=("MODEL_OR_TRACE_INVALID",),
        )

    if len(trace.events) > declaration.runtime_coordinate.maximum_events:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            event_count=len(trace.events),
            reasons=("DECLARED_EVENT_BUDGET_EXHAUSTED",),
        )
    expected_trace_coordinates = (
        declaration.authority_model_digest,
        declaration.executable_artifact_digest,
        declaration.deployed_artifact_digest,
        runtime_digest,
    )
    actual_trace_coordinates = (
        trace.authority_model_digest,
        trace.executable_artifact_digest,
        trace.deployed_artifact_digest,
        trace.runtime_coordinate_digest,
    )
    if actual_trace_coordinates != expected_trace_coordinates:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            event_count=len(trace.events),
            reasons=("TRACE_COORDINATE_SUBSTITUTION",),
        )

    transitions = {item.transition_id: item for item in model.transitions}
    model_states = {item.state_id for item in model.states}
    denominator = set(declaration.coverage_transition_ids)
    if declaration.initial_state_id not in model.initial_state_ids:
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            event_count=len(trace.events),
            reasons=("INITIAL_STATE_BINDING_INVALID",),
        )
    if not denominator <= set(transitions):
        return _new_receipt(
            declaration_bytes,
            retained,
            runtime_coordinate_digest=runtime_digest,
            coordinate_binding=coordinate_binding,
            correspondence=CorrespondenceVerdict.INVALID,
            coverage=CoverageCompleteness.INVALID,
            event_count=len(trace.events),
            reasons=("DENOMINATOR_TRANSITION_BINDING_INVALID",),
        )

    mapping_by_signature = {item.event_signature: item for item in declaration.transition_mappings}
    for mapping in declaration.transition_mappings:
        transition = transitions[mapping.authority_transition_id]
        if (mapping.actor_scope, mapping.action) != (transition.actor_scope, transition.action):
            return _new_receipt(
                declaration_bytes,
                retained,
                runtime_coordinate_digest=runtime_digest,
                coordinate_binding=coordinate_binding,
                correspondence=CorrespondenceVerdict.REFUTED,
                event_count=len(trace.events),
                reasons=("MAPPING_ACTOR_OR_ACTION_MISMATCH",),
            )

    current_state = declaration.initial_state_id
    reconstructed = [current_state]
    observed: set[str] = set()
    for event in trace.events:
        mapping = mapping_by_signature.get(event.event_signature)
        if mapping is None:
            return _new_receipt(
                declaration_bytes,
                retained,
                runtime_coordinate_digest=runtime_digest,
                coordinate_binding=coordinate_binding,
                correspondence=CorrespondenceVerdict.REFUTED,
                event_count=len(trace.events),
                covered=tuple(observed),
                states=tuple(reconstructed),
                reasons=("OBSERVED_EVENT_HAS_NO_EXACT_MAPPING",),
            )
        transition = transitions[mapping.authority_transition_id]
        if transition.source_state_id != current_state or transition.target_state_id not in model_states:
            return _new_receipt(
                declaration_bytes,
                retained,
                runtime_coordinate_digest=runtime_digest,
                coordinate_binding=coordinate_binding,
                correspondence=CorrespondenceVerdict.REFUTED,
                event_count=len(trace.events),
                covered=tuple(observed),
                states=tuple(reconstructed),
                reasons=("OBSERVED_TRANSITION_IMPOSSIBLE_FROM_RECONSTRUCTED_STATE",),
            )
        observed.add(transition.transition_id)
        current_state = transition.target_state_id
        reconstructed.append(current_state)

    coverage = CoverageCompleteness.COMPLETE if observed == denominator else CoverageCompleteness.INCOMPLETE
    reasons = () if coverage is CoverageCompleteness.COMPLETE else ("FINITE_DENOMINATOR_INCOMPLETE",)
    return _new_receipt(
        declaration_bytes,
        retained,
        runtime_coordinate_digest=runtime_digest,
        coordinate_binding=coordinate_binding,
        correspondence=CorrespondenceVerdict.ESTABLISHED,
        coverage=coverage,
        event_count=len(trace.events),
        covered=tuple(observed),
        states=tuple(reconstructed),
        reasons=reasons,
    )


def recheck_runtime_authority_correspondence_receipt(
    receipt_bytes: bytes,
    deriver_executable_path: str | Path | None = None,
) -> ReceiptRecheck:
    """Rebuild a receipt from retained bytes and reject forged result fields."""

    try:
        value = _decode_canonical(receipt_bytes, RECEIPT_SCHEMA, MAX_RECEIPT_BYTES)
        receipt = RuntimeAuthorityReceipt.from_dict(value)
        if receipt.receipt_digest is None or not hmac.compare_digest(receipt.receipt_digest, receipt.canonical_digest()):
            raise RuntimeAuthorityInvalid("receipt digest mismatch")
        declaration_bytes = _decode_base64(receipt.declaration_base64)
        if not hmac.compare_digest(digest_bytes(declaration_bytes), receipt.declaration_digest):
            raise RuntimeAuthorityInvalid("declaration digest mismatch")
        evidence = {item.coordinate: item.payload() for item in receipt.retained_evidence}
        rebuilt = build_runtime_authority_correspondence_receipt(
            declaration_bytes,
            evidence,
            deriver_executable_path,
        )
        if rebuilt.to_bytes() != receipt.to_bytes():
            raise RuntimeAuthorityInvalid("receipt result does not reproduce")
        return ReceiptRecheck(CorrespondenceVerdict.ESTABLISHED, (), receipt.receipt_digest)
    except RuntimeAuthorityUnsupported:
        return ReceiptRecheck(CorrespondenceVerdict.UNKNOWN, ("RECEIPT_UNSUPPORTED",), None)
    except RuntimeAuthorityLimit:
        return ReceiptRecheck(CorrespondenceVerdict.UNKNOWN, ("RECEIPT_LIMIT_EXHAUSTED",), None)
    except (RuntimeAuthorityInvalid, ValueError, TypeError, KeyError, AttributeError):
        return ReceiptRecheck(CorrespondenceVerdict.INVALID, ("RECEIPT_INVALID_OR_FORGED",), None)


__all__ = [
    "CLAIM_BOUNDARY",
    "DECLARATION_SCHEMA",
    "PROFILE_SCHEMA",
    "RECEIPT_SCHEMA",
    "SUPPORTED_RUNTIME_KIND",
    "TRACE_SCHEMA",
    "CorrespondenceVerdict",
    "CoverageCompleteness",
    "DeriverExecutionEvidence",
    "ReceiptRecheck",
    "RetainedEvidence",
    "RuntimeAuthorityDeclaration",
    "RuntimeAuthorityError",
    "RuntimeAuthorityInvalid",
    "RuntimeAuthorityLimit",
    "RuntimeAuthorityReceipt",
    "RuntimeAuthorityUnsupported",
    "RuntimeCoordinate",
    "RuntimeTrace",
    "TraceEvent",
    "TransitionMapping",
    "build_runtime_authority_correspondence_receipt",
    "recheck_runtime_authority_correspondence_receipt",
    "runtime_authority_profile_bytes",
    "runtime_authority_profile_digest",
]
