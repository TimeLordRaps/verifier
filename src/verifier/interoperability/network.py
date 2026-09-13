"""Experimental Verifier Standard (VSTD) verification-artifact network.

Terminology: American Standard Code for Information Interchange (ASCII);
Hypertext Transfer Protocol (HTTP); Hypertext Transfer Protocol Secure (HTTPS);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
uniform resource locator (URL).

This module gives content-addressed artifacts a complete-snapshot silo format.
It checks byte identity, declared derivation closure, an explicit completeness
census, and authority axiom agency as separate propositions.  None of those
checks establishes artifact correctness, real-world publisher identity, or
permission to execute retained bytes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import unicodedata
from typing import Any, Iterable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request


OBJECT_SCHEMA = "VSTD-OBJECT-0.1"
COMMIT_SCHEMA = "VSTD-SILO-COMMIT-0.1"
HEAD_SCHEMA = "VSTD-SIGNED-HEAD-0.1"
PUBLISHER_SCHEMA = "VSTD-PUBLISHER-0.1"
KEY_CONTINUITY_SCHEMA = "VSTD-KEY-CONTINUITY-0.1"
DIRECTORY_SCHEMA = "VSTD-DIRECTORY-SNAPSHOT-0.1"
EXPORT_SCHEMA = "VSTD-SILO-EXPORT-0.1"
TRANSFER_SCHEMA = "VSTD-SILO-TRANSFER-0.1"
ASSESSMENT_SCHEMA = "VSTD-SILO-ASSESSMENT-0.1"
ASSESSMENT_RECEIPT_SCHEMA = "VSTD-SILO-ASSESSMENT-RECEIPT-0.1"
COMPOSITION_SCHEMA = "VSTD-SILO-COMPOSITION-0.1"
COMPOSITION_ASSESSMENT_SCHEMA = "VSTD-SILO-COMPOSITION-ASSESSMENT-0.1"
COMPOSITION_ASSESSMENT_RECEIPT_SCHEMA = "VSTD-SILO-COMPOSITION-ASSESSMENT-RECEIPT-0.1"
PUSH_REQUEST_SCHEMA = "VSTD-PUSH-REQUEST-0.1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_EXPORT_BYTES = 16 * 1024 * 1024
MAX_TRANSFER_BYTES = 16 * 1024 * 1024
MAX_TRANSFER_REDIRECTS = 3
TRANSFER_TIMEOUT_SECONDS = 10
MAX_EXPORT_ENTRIES = 1024
MAX_ENTRIES = 256
MAX_BOUNDARY_MEMBERS = 4096
STORE_DIRS = (
    "objects", "objects/sha256", "records", "records/commits", "records/heads",
    "records/publishers", "records/keys", "records/directories", "records/assessments",
)
STORE_DIRECTORIES = (
    "objects", "objects/sha256", "records", "records/commits", "records/heads",
    "records/publishers", "records/keys", "records/directories", "records/assessments",
)
SELF_DERIVATION_EVIDENCE_SCHEMA = "VSTD-SELF-DERIVATION-EVIDENCE-0.1"
SELF_DERIVATION_MECHANISM_SCHEMA = "VSTD-SELF-DERIVATION-MECHANISM-0.1"
AUTHORITY_MODEL_SCHEMA = "VSTD-AUTHORITY-MODEL-0.1"
SUPPORTED_RELATION_STRENGTHS = ("DERIVES",)

AUTHORITY_AXIOM_AGENCY = (
    "CHALLENGE_WITH_COUNTEREVIDENCE",
    "EXIT_COMPOSITION",
    "EXPORT_ACCESSIBLE_SILO",
    "FORK_DERIVATION",
    "INDEPENDENTLY_INSPECT_ACCESSIBLE_ARTIFACTS",
    "PRESERVE_CONFLICT",
    "PRESERVE_UNKNOWN",
    "SELECT_TRUST_ROOTS",
    "WITHDRAW_OWN_AUTHORIZATION",
)
AUTHORITY_AXIOM_AGENCY_VERSION = "VSTD-AUTHORITY-AXIOM-AGENCY-0.1"
AUTHORITY_ACTOR_SCOPES = ("ANY_ACTOR",)
AUTHORITY_ACTOR_SCOPE_VERSION = "VSTD-AUTHORITY-ACTOR-SCOPE-0.1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PUBLISHER = re.compile(r"publisher:sha256:[0-9a-f]{64}\Z")
_PATH_PART = re.compile(r"[A-Za-z0-9_.-]+\Z")


class NetworkError(ValueError):
    """A network record or store operation failed closed."""


def _canonical_value(value: Any) -> None:
    if value is None or type(value) in {bool, str}:
        if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise NetworkError("canonical strings must not contain surrogate code points")
        if isinstance(value, str) and unicodedata.normalize("NFC", value) != value:
            raise NetworkError("canonical strings must use Unicode Normalization Form C")
        return
    if type(value) is int:
        if not 0 <= value <= 2**53 - 1:
            raise NetworkError("canonical integers must be nonnegative and exactly representable by JavaScript runtimes")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _canonical_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", key):
                raise NetworkError("canonical object keys must be lowercase ASCII snake_case")
            _canonical_value(item)
        return
    raise NetworkError("canonical JSON permits objects, arrays, strings, booleans, null, and JavaScript-safe integers only")


def canonical_bytes(value: Any) -> bytes:
    """Return the alpha canonical JSON byte representation."""

    _canonical_value(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NetworkError("value is not canonicalizable bounded JSON") from exc


def _read_bounded_regular(path: str | Path, maximum: int, label: str) -> bytes:
    source = Path(path)
    try:
        before = source.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise NetworkError(f"{label} must be an ordinary non-link file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(source, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise NetworkError(f"{label} changed during open")
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise NetworkError(f"cannot read {label}") from exc
    if len(data) > maximum:
        raise NetworkError(f"{label} exceeds its byte bound")
    return data


def self_derivation_mechanism_bytes() -> bytes:
    """Return the only alpha mechanism interpreted by ``assess_silo``."""

    return canonical_bytes({
        "schema_version": SELF_DERIVATION_MECHANISM_SCHEMA,
        "mechanism_id": "vstd.reference.structural_self_derivation.0.1",
        "relation_strength": "DERIVES",
        "rules": [
            "ground_self_requires_declared_ground_and_retained_path_origin",
            "derivation_reflexivity_requires_grounded_necessary_mechanism_and_derived_evidence",
            "reflexion_identity_requires_exact_subject_and_terminal_edge",
            "deriver_cycle_closure_requires_continuous_retained_graph_and_no_residuals",
        ],
        "claim_boundary": "This mechanism checks a retained structural self-derivation witness. It does not prove semantic self-return, truth, or completeness.",
    })


def silo_composition_mechanism_bytes() -> bytes:
    """Return the canonical alpha mechanism used by composition receipts."""

    return canonical_bytes({
        "schema_version": "VSTD-SILO-COMPOSITION-MECHANISM-0.1",
        "mechanism_id": "vstd.reference.silo_composition.0.1",
        "rules": [
            "recompute_every_member_silo_assessment",
            "require_exact_declared_member_commit_digests",
            "recompute_optional_composite_silo_assessment",
            "require_exact_composite_member_artifacts_and_composition_surfaces",
            "require_established_silo_grounding_for_every_member_and_composite",
            "preserve_ground_authority_and_composition_preserved_local_additions",
            "admit_only_when_every_member_and_composite_axis_passes",
        ],
        "claim_boundary": "This mechanism checks exact declared silo composition structure and nested independent assessments. It does not establish artifact truth, actual runtime behavior, or compatibility beyond the retained composition evidence.",
    })


def digest_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise NetworkError("content-addressed values must be immutable bytes")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def authority_axiom_agency_digest(actions: Sequence[str] = AUTHORITY_AXIOM_AGENCY) -> str:
    """Bind the exact agency version and sorted action set."""

    return digest_bytes(canonical_bytes({"schema_version": AUTHORITY_AXIOM_AGENCY_VERSION, "actions": sorted(actions)}))


def authority_actor_scope_digest(scopes: Sequence[str] = AUTHORITY_ACTOR_SCOPES) -> str:
    """Bind the exact alpha actor-scope vocabulary."""

    return digest_bytes(canonical_bytes({"schema_version": AUTHORITY_ACTOR_SCOPE_VERSION, "actor_scopes": sorted(scopes)}))


def _digest(value: Any, field: str = "digest") -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise NetworkError(f"{field} must be sha256 followed by 64 lowercase hexadecimal characters")
    return value


def _text(value: Any, field: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        raise NetworkError(f"{field} must be bounded nonempty text without control characters")
    return value


def _path(value: Any) -> str:
    value = _text(value, "logical path", maximum=240)
    parts = value.split("/")
    if any(
        not _PATH_PART.fullmatch(part) or part in {".", ".."} or part.endswith(".")
        or part.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL"}
        or re.fullmatch(r"(?:COM|LPT)[1-9]", part.split(".", 1)[0].upper())
        for part in parts
    ):
        raise NetworkError("logical paths must be portable relative ASCII paths")
    return value


def _strict(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NetworkError(f"{label} must have exactly its defined fields")
    return value


def _canonical_record(value: Mapping[str, Any], record: Any, label: str) -> Any:
    """Reject wire records whose ordered members were silently normalized.

    Constructors sort set-like members for ergonomic programmatic use. A wire
    decoder must instead require the sender's representation to already be
    canonical so independently implemented runtimes accept the same bytes.
    """

    if canonical_bytes(value) != canonical_bytes(record.to_dict()):
        raise NetworkError(f"{label} is not in canonical member order")
    return record


def _array(value: Any, label: str, maximum: int = MAX_ENTRIES) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise NetworkError(f"{label} must be an array of at most {maximum} items")
    return tuple(value)


def _unique(values: Iterable[str], label: str) -> tuple[str, ...]:
    result = tuple(sorted(values))
    if len(result) != len(set(result)):
        raise NetworkError(f"{label} contains duplicates")
    return result


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _canonical_b64(value: Any, length: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise NetworkError(f"{field} must be base64 text")
    try:
        if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise NetworkError(f"{field} is not canonical unpadded base64url") from exc
    if len(decoded) != length or _base64url_encode(decoded) != value:
        raise NetworkError(f"{field} is not canonical unpadded base64url of the required length")
    return decoded


@dataclass(frozen=True)
class ObjectRecord:
    """Exact payload identity plus declarations that do not establish semantics."""

    object_digest: str
    size_bytes: int
    media_type: str
    artifact_kind: str
    declared_schema_id: str
    schema_version: str = OBJECT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OBJECT_SCHEMA:
            raise NetworkError("unsupported object schema_version")
        _digest(self.object_digest, "object_digest")
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= MAX_OBJECT_BYTES:
            raise NetworkError("size_bytes must be a bounded nonnegative integer")
        _text(self.media_type, "media_type", maximum=256)
        _text(self.artifact_kind, "artifact_kind", maximum=128)
        _text(self.declared_schema_id, "declared_schema_id", maximum=256)

    @classmethod
    def from_payload(cls, payload: bytes, media_type: str, artifact_kind: str,
                     declared_schema_id: str = "NOT_DECLARED") -> "ObjectRecord":
        if len(payload) > MAX_OBJECT_BYTES:
            raise NetworkError("object exceeds the byte bound")
        return cls(digest_bytes(payload), len(payload), media_type, artifact_kind, declared_schema_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "object_digest": self.object_digest,
            "size_bytes": self.size_bytes, "media_type": self.media_type,
            "artifact_kind": self.artifact_kind, "declared_schema_id": self.declared_schema_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObjectRecord":
        value = _strict(value, {"schema_version", "object_digest", "size_bytes", "media_type", "artifact_kind", "declared_schema_id"}, "object record")
        return _canonical_record(value, cls(**value), "object record")


@dataclass(frozen=True)
class CensusEntry:
    """One member of the commit's explicit completeness denominator."""

    path: str
    object_record: ObjectRecord
    necessity: str

    def __post_init__(self) -> None:
        _path(self.path)
        if self.necessity not in {"NECESSARY", "DISPENSABLE"}:
            raise NetworkError("necessity must be NECESSARY or DISPENSABLE")

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "object": self.object_record.to_dict(), "necessity": self.necessity}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CensusEntry":
        value = _strict(value, {"path", "object", "necessity"}, "census entry")
        return _canonical_record(
            value, cls(value["path"], ObjectRecord.from_dict(value["object"]), value["necessity"]),
            "census entry",
        )


@dataclass(frozen=True)
class DerivationEdge:
    """Declared formation path; declaration alone is not semantic correctness."""

    target_path: str
    premise_paths: tuple[str, ...]
    mechanism_path: str
    relation_strength: str = "DERIVES"

    def __post_init__(self) -> None:
        _path(self.target_path)
        _path(self.mechanism_path)
        if self.relation_strength not in SUPPORTED_RELATION_STRENGTHS:
            raise NetworkError("unsupported derivation relation_strength")
        object.__setattr__(self, "premise_paths", _unique((_path(item) for item in self.premise_paths), "premise_paths"))

    def to_dict(self) -> dict[str, Any]:
        return {"target_path": self.target_path, "premise_paths": list(self.premise_paths), "mechanism_path": self.mechanism_path, "relation_strength": self.relation_strength}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DerivationEdge":
        value = _strict(value, {"target_path", "premise_paths", "mechanism_path", "relation_strength"}, "derivation edge")
        return _canonical_record(
            value, cls(value["target_path"], tuple(_array(value["premise_paths"], "premise_paths")), value["mechanism_path"], value["relation_strength"]),
            "derivation edge",
        )


@dataclass(frozen=True)
class ArtifactRelation:
    """Exact typed relation; only a named mechanism may establish contradiction."""

    relation_type: str
    source_path: str
    target_path: str
    mechanism_path: str | None
    semantic_coordinate: str | None

    def __post_init__(self) -> None:
        if self.relation_type not in {"EVIDENCES", "CHECKS", "REFUTES", "CHALLENGES", "SUPERSEDES", "REVOKES"}:
            raise NetworkError("unsupported artifact relation_type")
        _path(self.source_path)
        _path(self.target_path)
        if self.mechanism_path is not None:
            _path(self.mechanism_path)
        if self.semantic_coordinate is not None:
            _text(self.semantic_coordinate, "semantic_coordinate", maximum=512)

    def to_dict(self) -> dict[str, Any]:
        return {"relation_type": self.relation_type, "source_path": self.source_path, "target_path": self.target_path, "mechanism_path": self.mechanism_path, "semantic_coordinate": self.semantic_coordinate}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRelation":
        value = _strict(value, {"relation_type", "source_path", "target_path", "mechanism_path", "semantic_coordinate"}, "artifact relation")
        return _canonical_record(value, cls(**value), "artifact relation")


@dataclass(frozen=True)
class LocalAuthorityAddition:
    """One additive actor-scoped allowance; it cannot revoke ground agency."""

    actor_scope: str
    action: str
    propagation: str

    def __post_init__(self) -> None:
        _text(self.actor_scope, "local authority actor_scope", maximum=128)
        _text(self.action, "local authority action", maximum=128)
        if self.action in AUTHORITY_AXIOM_AGENCY:
            raise NetworkError("local authority additions must not duplicate ground actions")
        if self.propagation not in {"LOCAL_ONLY", "COMPOSITION_PRESERVED"}:
            raise NetworkError("local authority propagation must be LOCAL_ONLY or COMPOSITION_PRESERVED")

    def to_dict(self) -> dict[str, Any]:
        return {"actor_scope": self.actor_scope, "action": self.action, "propagation": self.propagation}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LocalAuthorityAddition":
        value = _strict(value, {"actor_scope", "action", "propagation"}, "local authority addition")
        return _canonical_record(value, cls(**value), "local authority addition")

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class AuthorityState:
    """Declared allowable actions at one finite authority-model state."""

    state_id: str
    ground_actions: tuple[str, ...]
    local_authority_additions: tuple[LocalAuthorityAddition, ...]

    def __post_init__(self) -> None:
        _text(self.state_id, "authority state_id", maximum=128)
        object.__setattr__(self, "ground_actions", _unique((_text(item, "ground action", maximum=128) for item in self.ground_actions), "authority state ground_actions"))
        if len(self.local_authority_additions) > MAX_ENTRIES or not all(isinstance(item, LocalAuthorityAddition) for item in self.local_authority_additions):
            raise NetworkError("local_authority_additions must contain at most 256 typed additions")
        additions = tuple(sorted(self.local_authority_additions, key=lambda item: item.canonical_digest()))
        if len({item.canonical_digest() for item in additions}) != len(additions):
            raise NetworkError("local_authority_additions contains duplicates")
        object.__setattr__(self, "local_authority_additions", additions)

    def to_dict(self) -> dict[str, Any]:
        return {"state_id": self.state_id, "ground_actions": list(self.ground_actions), "local_authority_additions": [item.to_dict() for item in self.local_authority_additions]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityState":
        value = _strict(value, {"state_id", "ground_actions", "local_authority_additions"}, "authority state")
        return _canonical_record(
            value, cls(value["state_id"], tuple(_array(value["ground_actions"], "ground_actions")), tuple(LocalAuthorityAddition.from_dict(item) for item in _array(value["local_authority_additions"], "local_authority_additions"))),
            "authority state",
        )


@dataclass(frozen=True)
class AuthorityTransition:
    """One edge in the exact finite declared authority transition graph."""

    transition_id: str
    source_state_id: str
    target_state_id: str
    actor_scope: str
    action: str

    def __post_init__(self) -> None:
        for field in ("transition_id", "source_state_id", "target_state_id"):
            _text(getattr(self, field), f"authority {field}", maximum=128)
        _text(self.actor_scope, "authority transition actor_scope", maximum=128)
        _text(self.action, "authority transition action", maximum=128)

    def to_dict(self) -> dict[str, Any]:
        return {"transition_id": self.transition_id, "source_state_id": self.source_state_id, "target_state_id": self.target_state_id, "actor_scope": self.actor_scope, "action": self.action}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityTransition":
        value = _strict(value, {"transition_id", "source_state_id", "target_state_id", "actor_scope", "action"}, "authority transition")
        return _canonical_record(value, cls(**value), "authority transition")


@dataclass(frozen=True)
class AuthorityModel:
    """Finite declarative model interpreted by the alpha authority checker."""

    authority_axiom_agency_version: str
    authority_axiom_agency_digest: str
    actor_scope_version: str
    actor_scope_digest: str
    initial_state_ids: tuple[str, ...]
    state_universe: tuple[str, ...]
    transition_universe: tuple[str, ...]
    states: tuple[AuthorityState, ...]
    transitions: tuple[AuthorityTransition, ...]
    closure_status: str
    residual_obligations: tuple[str, ...]
    schema_version: str = AUTHORITY_MODEL_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORITY_MODEL_SCHEMA:
            raise NetworkError("unsupported authority model schema_version")
        _text(self.authority_axiom_agency_version, "authority model agency version", maximum=128)
        _digest(self.authority_axiom_agency_digest, "authority model agency digest")
        _text(self.actor_scope_version, "authority actor-scope version", maximum=128)
        _digest(self.actor_scope_digest, "authority actor-scope digest")
        object.__setattr__(self, "initial_state_ids", _unique((_text(item, "initial state_id", maximum=128) for item in self.initial_state_ids), "initial_state_ids"))
        object.__setattr__(self, "state_universe", _unique((_text(item, "state universe member", maximum=128) for item in self.state_universe), "state_universe"))
        object.__setattr__(self, "transition_universe", _unique((_text(item, "transition universe member", maximum=128) for item in self.transition_universe), "transition_universe"))
        if not self.states or len(self.states) > MAX_ENTRIES or len(self.transitions) > MAX_ENTRIES or not all(isinstance(item, AuthorityState) for item in self.states) or not all(isinstance(item, AuthorityTransition) for item in self.transitions):
            raise NetworkError("authority model requires one to 256 states and at most 256 transitions")
        states = tuple(sorted(self.states, key=lambda item: item.state_id))
        transitions = tuple(sorted(self.transitions, key=lambda item: item.transition_id))
        if len({item.state_id for item in states}) != len(states) or len({item.transition_id for item in transitions}) != len(transitions):
            raise NetworkError("authority model identifiers must be unique")
        object.__setattr__(self, "states", states)
        object.__setattr__(self, "transitions", transitions)
        if self.closure_status not in {"CLOSED", "OPEN"}:
            raise NetworkError("authority closure_status must be CLOSED or OPEN")
        object.__setattr__(self, "residual_obligations", _unique((_text(item, "authority residual obligation") for item in self.residual_obligations), "authority residual_obligations"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_axiom_agency_version": self.authority_axiom_agency_version,
            "authority_axiom_agency_digest": self.authority_axiom_agency_digest,
            "actor_scope_version": self.actor_scope_version,
            "actor_scope_digest": self.actor_scope_digest,
            "initial_state_ids": list(self.initial_state_ids),
            "state_universe": list(self.state_universe),
            "transition_universe": list(self.transition_universe),
            "states": [item.to_dict() for item in self.states],
            "transitions": [item.to_dict() for item in self.transitions],
            "closure_status": self.closure_status,
            "residual_obligations": list(self.residual_obligations),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityModel":
        fields = {"schema_version", "authority_axiom_agency_version", "authority_axiom_agency_digest", "actor_scope_version", "actor_scope_digest", "initial_state_ids", "state_universe", "transition_universe", "states", "transitions", "closure_status", "residual_obligations"}
        value = _strict(value, fields, "authority model")
        record = cls(
            authority_axiom_agency_version=value["authority_axiom_agency_version"],
            authority_axiom_agency_digest=value["authority_axiom_agency_digest"],
            actor_scope_version=value["actor_scope_version"], actor_scope_digest=value["actor_scope_digest"],
            initial_state_ids=tuple(_array(value["initial_state_ids"], "initial_state_ids")),
            state_universe=tuple(_array(value["state_universe"], "state_universe")),
            transition_universe=tuple(_array(value["transition_universe"], "transition_universe")),
            states=tuple(AuthorityState.from_dict(item) for item in _array(value["states"], "authority states")),
            transitions=tuple(AuthorityTransition.from_dict(item) for item in _array(value["transitions"], "authority transitions")),
            closure_status=value["closure_status"], residual_obligations=tuple(_array(value["residual_obligations"], "authority residual obligations")),
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "authority model")


@dataclass(frozen=True)
class SelfDerivationRecord:
    """Declared terminal self-derivation path, independent of completeness."""

    subject_path: str
    ground_paths: tuple[str, ...]
    mechanism_path: str
    retained_path: tuple[str, ...]
    relation_strength: str
    ground_self: bool
    derivation_reflexivity: bool
    reflexion_identity: bool
    deriver_cycle_closed: bool
    ground_self_evidence_path: str
    derivation_reflexivity_evidence_path: str
    reflexion_identity_evidence_path: str
    deriver_cycle_closure_evidence_path: str
    residual_obligations: tuple[str, ...]

    def __post_init__(self) -> None:
        _path(self.subject_path)
        object.__setattr__(self, "ground_paths", _unique((_path(item) for item in self.ground_paths), "self-derivation ground_paths"))
        _path(self.mechanism_path)
        path = tuple(_path(item) for item in self.retained_path)
        if not path or path[0] not in self.ground_paths or path[-1] != self.subject_path:
            raise NetworkError("self-derivation retained_path must begin at ground and terminate at its subject")
        object.__setattr__(self, "retained_path", path)
        _text(self.relation_strength, "relation_strength", maximum=128)
        for field in ("ground_self", "derivation_reflexivity", "reflexion_identity", "deriver_cycle_closed"):
            if type(getattr(self, field)) is not bool:
                raise NetworkError(f"{field} must be boolean")
        for field in ("ground_self_evidence_path", "derivation_reflexivity_evidence_path", "reflexion_identity_evidence_path", "deriver_cycle_closure_evidence_path"):
            _path(getattr(self, field))
        object.__setattr__(self, "residual_obligations", _unique((_text(item, "self-derivation residual obligation") for item in self.residual_obligations), "self-derivation residual_obligations"))

    def to_dict(self) -> dict[str, Any]:
        return {"subject_path": self.subject_path, "ground_paths": list(self.ground_paths), "mechanism_path": self.mechanism_path, "retained_path": list(self.retained_path), "relation_strength": self.relation_strength, "ground_self": self.ground_self, "derivation_reflexivity": self.derivation_reflexivity, "reflexion_identity": self.reflexion_identity, "deriver_cycle_closed": self.deriver_cycle_closed, "ground_self_evidence_path": self.ground_self_evidence_path, "derivation_reflexivity_evidence_path": self.derivation_reflexivity_evidence_path, "reflexion_identity_evidence_path": self.reflexion_identity_evidence_path, "deriver_cycle_closure_evidence_path": self.deriver_cycle_closure_evidence_path, "residual_obligations": list(self.residual_obligations)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SelfDerivationRecord":
        value = _strict(value, {"subject_path", "ground_paths", "mechanism_path", "retained_path", "relation_strength", "ground_self", "derivation_reflexivity", "reflexion_identity", "deriver_cycle_closed", "ground_self_evidence_path", "derivation_reflexivity_evidence_path", "reflexion_identity_evidence_path", "deriver_cycle_closure_evidence_path", "residual_obligations"}, "self-derivation record")
        return _canonical_record(
            value,
            cls(value["subject_path"], tuple(_array(value["ground_paths"], "self-derivation ground_paths")), value["mechanism_path"], tuple(_array(value["retained_path"], "retained_path")), value["relation_strength"], value["ground_self"], value["derivation_reflexivity"], value["reflexion_identity"], value["deriver_cycle_closed"], value["ground_self_evidence_path"], value["derivation_reflexivity_evidence_path"], value["reflexion_identity_evidence_path"], value["deriver_cycle_closure_evidence_path"], tuple(_array(value["residual_obligations"], "self-derivation residual_obligations"))),
            "self-derivation record",
        )


def census_boundary_members(
    census: Sequence[CensusEntry],
    ground_paths: Sequence[str],
    derivations: Sequence[DerivationEdge],
    relations: Sequence[ArtifactRelation],
    authority_actions: Sequence[str],
    residual_obligations: Sequence[str],
    exclusions: Sequence[str],
    *,
    publisher_id: str,
    parents: Sequence[str],
    completeness_kind: str,
    authority_version: str,
    authority_digest: str,
    self_derivation_record: SelfDerivationRecord,
    created_at: str,
    authority_model_path: str | None = None,
    authority_model: AuthorityModel | None = None,
) -> tuple[str, ...]:
    members: set[str] = set()
    members.add(f"publisher:{publisher_id}")
    members.update(f"parent:{parent}" for parent in parents)
    members.add(f"completeness-kind:{completeness_kind}")
    members.add("self-derivation-record:" + digest_bytes(canonical_bytes(self_derivation_record.to_dict())))
    members.add("created-at:" + digest_bytes(created_at.encode("utf-8")))
    members.add(f"authority-binding:{authority_version}:{authority_digest}")
    if authority_model_path is None:
        members.add("authority-model:ABSENT")
    else:
        members.add(f"authority-model-path:{authority_model_path}")
        if authority_model is not None:
            members.add("authority-model:" + digest_bytes(canonical_bytes(authority_model.to_dict())))
            members.add(f"authority-actor-scope-binding:{authority_model.actor_scope_version}:{authority_model.actor_scope_digest}")
            members.update(f"authority-initial-state:{item}" for item in authority_model.initial_state_ids)
            members.update(f"authority-state-universe:{item}" for item in authority_model.state_universe)
            members.update(f"authority-transition-universe:{item}" for item in authority_model.transition_universe)
            for state in authority_model.states:
                members.add("authority-state:" + digest_bytes(canonical_bytes(state.to_dict())))
                members.update(f"authority-state-ground-action:{state.state_id}:{action}" for action in state.ground_actions)
                members.update("local-authority-addition:" + addition.canonical_digest() for addition in state.local_authority_additions)
            members.update("authority-transition:" + digest_bytes(canonical_bytes(item.to_dict())) for item in authority_model.transitions)
            members.update("authority-residual:" + digest_bytes(item.encode("utf-8")) for item in authority_model.residual_obligations)
    for entry in census:
        members.add(f"object:{entry.path}")
        members.add(f"necessity:{entry.path}:{entry.necessity}")
    members.update(f"ground-path:{path}" for path in ground_paths)
    for edge in derivations:
        members.add("derivation:" + digest_bytes(canonical_bytes(edge.to_dict())))
        members.add("mechanism-dependency:" + digest_bytes(canonical_bytes({
            "target_path": edge.target_path,
            "mechanism_path": edge.mechanism_path,
        })))
        members.update(
            "premise-dependency:" + digest_bytes(canonical_bytes({
                "target_path": edge.target_path,
                "premise_path": path,
            }))
            for path in edge.premise_paths
        )
    members.update("relation:" + digest_bytes(canonical_bytes(relation.to_dict())) for relation in relations)
    members.update(f"authority-action:{action}" for action in authority_actions)
    members.update("residual:" + digest_bytes(item.encode("utf-8")) for item in residual_obligations)
    members.update("exclusion:" + digest_bytes(item.encode("utf-8")) for item in exclusions)
    return tuple(sorted(members))


@dataclass(frozen=True)
class SiloCommit:
    """Complete logical snapshot with ground, census, derivations, and agency."""

    publisher_id: str
    parents: tuple[str, ...]
    census: tuple[CensusEntry, ...]
    ground_paths: tuple[str, ...]
    derivations: tuple[DerivationEdge, ...]
    relations: tuple[ArtifactRelation, ...]
    residual_obligations: tuple[str, ...]
    exclusions: tuple[str, ...]
    completeness_kind: str
    coverage_universe: tuple[str, ...]
    authority_axiom_agency: tuple[str, ...]
    authority_axiom_agency_version: str
    authority_axiom_agency_digest: str
    authority_model_path: str | None
    self_derivation_record: SelfDerivationRecord
    created_at: str
    schema_version: str = COMMIT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMMIT_SCHEMA:
            raise NetworkError("unsupported silo commit schema_version")
        if not isinstance(self.publisher_id, str) or not _PUBLISHER.fullmatch(self.publisher_id):
            raise NetworkError("publisher_id must derive from a SHA-256 public-key digest")
        if len(self.parents) > 2:
            raise NetworkError("alpha commits have at most two parents")
        object.__setattr__(self, "parents", _unique((_digest(item, "parent") for item in self.parents), "parents"))
        entries = tuple(sorted(self.census, key=lambda item: item.path))
        if not entries or len(entries) > MAX_ENTRIES or not all(isinstance(item, CensusEntry) for item in entries):
            raise NetworkError("census must contain one to 256 entries")
        paths = tuple(item.path for item in entries)
        if len(paths) != len(set(path.casefold() for path in paths)):
            raise NetworkError("census paths must be unique without case collisions")
        object.__setattr__(self, "census", entries)
        object.__setattr__(self, "ground_paths", _unique((_path(item) for item in self.ground_paths), "ground_paths"))
        derivations = tuple(sorted(self.derivations, key=lambda item: item.target_path))
        if len(derivations) != len(set(item.target_path for item in derivations)):
            raise NetworkError("derivation targets must be unique")
        object.__setattr__(self, "derivations", derivations)
        relations = tuple(sorted(self.relations, key=lambda item: (item.relation_type, item.source_path, item.target_path)))
        if len(relations) > MAX_ENTRIES or not all(isinstance(item, ArtifactRelation) for item in relations):
            raise NetworkError("relations must contain at most 256 typed relations")
        object.__setattr__(self, "relations", relations)
        object.__setattr__(self, "residual_obligations", _unique((_text(item, "residual obligation") for item in self.residual_obligations), "residual_obligations"))
        object.__setattr__(self, "exclusions", _unique((_text(item, "census exclusion") for item in self.exclusions), "exclusions"))
        if self.completeness_kind not in {"SILO_CENSUS", "DERIVATIONAL_COVERAGE", "SEMANTIC_COVERAGE", "LOGICAL_DECIDABILITY"}:
            raise NetworkError("unsupported completeness_kind")
        if len(self.coverage_universe) > MAX_BOUNDARY_MEMBERS:
            raise NetworkError("coverage_universe exceeds the typed boundary-member limit")
        object.__setattr__(self, "coverage_universe", _unique((_text(item, "coverage boundary member", maximum=512) for item in self.coverage_universe), "coverage_universe"))
        object.__setattr__(self, "authority_axiom_agency", _unique((_text(item, "authority action", maximum=128) for item in self.authority_axiom_agency), "authority_axiom_agency"))
        _text(self.authority_axiom_agency_version, "authority_axiom_agency_version", maximum=128)
        _digest(self.authority_axiom_agency_digest, "authority_axiom_agency_digest")
        if self.authority_model_path is not None:
            _path(self.authority_model_path)
        if not isinstance(self.self_derivation_record, SelfDerivationRecord):
            raise NetworkError("self_derivation_record must be explicit")
        known = set(paths)
        referenced = set(self.ground_paths)
        referenced |= {self.self_derivation_record.subject_path, self.self_derivation_record.mechanism_path, *self.self_derivation_record.ground_paths, *self.self_derivation_record.retained_path}
        referenced |= {self.self_derivation_record.ground_self_evidence_path, self.self_derivation_record.derivation_reflexivity_evidence_path, self.self_derivation_record.reflexion_identity_evidence_path, self.self_derivation_record.deriver_cycle_closure_evidence_path}
        if self.authority_model_path is not None:
            referenced.add(self.authority_model_path)
        for edge in derivations:
            referenced |= {edge.target_path, edge.mechanism_path, *edge.premise_paths}
        for relation in relations:
            referenced |= {relation.source_path, relation.target_path}
            if relation.mechanism_path is not None:
                referenced.add(relation.mechanism_path)
        if not referenced <= known:
            raise NetworkError("ground, mechanism, premise, and target paths must be census members")
        _text(self.created_at, "created_at", maximum=64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "publisher_id": self.publisher_id,
            "parents": list(self.parents), "census": [item.to_dict() for item in self.census],
            "ground_paths": list(self.ground_paths), "derivations": [item.to_dict() for item in self.derivations],
            "relations": [item.to_dict() for item in self.relations],
            "residual_obligations": list(self.residual_obligations),
            "exclusions": list(self.exclusions),
            "completeness_kind": self.completeness_kind,
            "coverage_universe": list(self.coverage_universe),
            "authority_axiom_agency": list(self.authority_axiom_agency),
            "authority_axiom_agency_version": self.authority_axiom_agency_version,
            "authority_axiom_agency_digest": self.authority_axiom_agency_digest,
            "authority_model_path": self.authority_model_path,
            "self_derivation_record": self.self_derivation_record.to_dict(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloCommit":
        fields = {"schema_version", "publisher_id", "parents", "census", "ground_paths", "derivations", "relations", "residual_obligations", "exclusions", "completeness_kind", "coverage_universe", "authority_axiom_agency", "authority_axiom_agency_version", "authority_axiom_agency_digest", "authority_model_path", "self_derivation_record", "created_at"}
        value = _strict(value, fields, "silo commit")
        record = cls(
            publisher_id=value["publisher_id"], parents=tuple(_array(value["parents"], "parents")),
            census=tuple(CensusEntry.from_dict(item) for item in _array(value["census"], "census")),
            ground_paths=tuple(_array(value["ground_paths"], "ground_paths")),
            derivations=tuple(DerivationEdge.from_dict(item) for item in _array(value["derivations"], "derivations")),
            relations=tuple(ArtifactRelation.from_dict(item) for item in _array(value["relations"], "relations")),
            residual_obligations=tuple(_array(value["residual_obligations"], "residual_obligations")),
            exclusions=tuple(_array(value["exclusions"], "exclusions")),
            completeness_kind=value["completeness_kind"],
            coverage_universe=tuple(_array(value["coverage_universe"], "coverage_universe", MAX_BOUNDARY_MEMBERS)),
            authority_axiom_agency=tuple(_array(value["authority_axiom_agency"], "authority_axiom_agency")),
            authority_axiom_agency_version=value["authority_axiom_agency_version"],
            authority_axiom_agency_digest=value["authority_axiom_agency_digest"],
            authority_model_path=value["authority_model_path"],
            self_derivation_record=SelfDerivationRecord.from_dict(value["self_derivation_record"]), schema_version=value["schema_version"],
            created_at=value["created_at"],
        )
        return _canonical_record(value, record, "silo commit")

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class PublisherRecord:
    publisher_id: str
    genesis_public_key_base64url: str
    active_key_ids: tuple[str, ...]
    key_continuity_digests: tuple[str, ...]
    display_name: str
    description: str
    schema_version: str = PUBLISHER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != PUBLISHER_SCHEMA:
            raise NetworkError("unsupported publisher schema_version")
        raw = _canonical_b64(self.genesis_public_key_base64url, 32, "genesis_public_key_base64url")
        expected = "publisher:" + digest_bytes(raw)
        if self.publisher_id != expected:
            raise NetworkError("publisher_id does not derive from the genesis public key")
        object.__setattr__(self, "active_key_ids", _unique((_digest(item, "key identifier") for item in self.active_key_ids), "active_key_ids"))
        object.__setattr__(self, "key_continuity_digests", _unique((_digest(item, "key continuity digest") for item in self.key_continuity_digests), "key_continuity_digests"))
        if not self.active_key_ids:
            raise NetworkError("publisher must declare at least one active key")
        _text(self.display_name, "display_name", maximum=256)
        _text(self.description, "description")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "publisher_id": self.publisher_id, "genesis_public_key_base64url": self.genesis_public_key_base64url, "active_key_ids": list(self.active_key_ids), "key_continuity_digests": list(self.key_continuity_digests), "display_name": self.display_name, "description": self.description}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PublisherRecord":
        value = _strict(value, {"schema_version", "publisher_id", "genesis_public_key_base64url", "active_key_ids", "key_continuity_digests", "display_name", "description"}, "publisher record")
        return _canonical_record(
            value, cls(value["publisher_id"], value["genesis_public_key_base64url"], tuple(_array(value["active_key_ids"], "active_key_ids")), tuple(_array(value["key_continuity_digests"], "key_continuity_digests")), value["display_name"], value["description"], value["schema_version"]),
            "publisher record",
        )


@dataclass(frozen=True)
class SignedHead:
    publisher_id: str
    sequence: int
    commit_digest: str
    previous_head_digest: str | None
    key_id: str
    issued_at: str
    public_key_base64url: str
    signature_base64url: str
    schema_version: str = HEAD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != HEAD_SCHEMA or not _PUBLISHER.fullmatch(self.publisher_id):
            raise NetworkError("invalid signed head schema or publisher")
        if type(self.sequence) is not int or not 0 <= self.sequence <= 2**53 - 1:
            raise NetworkError("head sequence must be a nonnegative integer")
        _digest(self.commit_digest, "commit_digest")
        if self.previous_head_digest is not None:
            _digest(self.previous_head_digest, "previous_head_digest")
        _digest(self.key_id, "key_id")
        raw = _canonical_b64(self.public_key_base64url, 32, "public_key_base64url")
        if digest_bytes(raw) != self.key_id:
            raise NetworkError("key_id does not bind the public key")
        _canonical_b64(self.signature_base64url, 64, "signature_base64url")
        _text(self.issued_at, "issued_at", maximum=64)

    def signing_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "publisher_id": self.publisher_id, "sequence": self.sequence, "commit_digest": self.commit_digest, "previous_head_digest": self.previous_head_digest, "key_id": self.key_id, "issued_at": self.issued_at, "public_key_base64url": self.public_key_base64url}

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_dict(), "signature_base64url": self.signature_base64url}

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedHead":
        value = _strict(value, {"schema_version", "publisher_id", "sequence", "commit_digest", "previous_head_digest", "key_id", "issued_at", "public_key_base64url", "signature_base64url"}, "signed head")
        return _canonical_record(value, cls(**value), "signed head")


@dataclass(frozen=True)
class KeyContinuityRecord:
    """Dual-signed key rotation; loss of the old key cannot imply continuity."""

    publisher_id: str
    previous_key_base64url: str
    new_key_base64url: str
    sequence: int
    previous_record_digest: str | None
    old_signature_base64url: str
    new_signature_base64url: str
    schema_version: str = KEY_CONTINUITY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != KEY_CONTINUITY_SCHEMA or not _PUBLISHER.fullmatch(self.publisher_id):
            raise NetworkError("invalid key continuity schema or publisher")
        if type(self.sequence) is not int or not 1 <= self.sequence <= 2**53 - 1:
            raise NetworkError("key continuity sequence must be positive")
        if self.previous_record_digest is not None:
            _digest(self.previous_record_digest, "previous_record_digest")
        _canonical_b64(self.previous_key_base64url, 32, "previous_key_base64url")
        _canonical_b64(self.new_key_base64url, 32, "new_key_base64url")
        _canonical_b64(self.old_signature_base64url, 64, "old_signature_base64url")
        _canonical_b64(self.new_signature_base64url, 64, "new_signature_base64url")

    def signing_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "publisher_id": self.publisher_id, "previous_key_base64url": self.previous_key_base64url, "new_key_base64url": self.new_key_base64url, "sequence": self.sequence, "previous_record_digest": self.previous_record_digest}

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_dict(), "old_signature_base64url": self.old_signature_base64url, "new_signature_base64url": self.new_signature_base64url}

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "KeyContinuityRecord":
        value = _strict(value, {"schema_version", "publisher_id", "previous_key_base64url", "new_key_base64url", "sequence", "previous_record_digest", "old_signature_base64url", "new_signature_base64url"}, "key continuity record")
        return _canonical_record(value, cls(**value), "key continuity record")


@dataclass(frozen=True)
class DirectoryEntry:
    """Discovery metadata; listing does not establish publisher identity or trust."""

    publisher_id: str
    head_digest: str
    endpoint: str
    visibility: str

    def __post_init__(self) -> None:
        if not _PUBLISHER.fullmatch(self.publisher_id):
            raise NetworkError("directory publisher_id is invalid")
        _digest(self.head_digest, "head_digest")
        _text(self.endpoint, "endpoint")
        if self.visibility not in {"LISTED", "DELISTED", "QUARANTINED", "UNKNOWN"}:
            raise NetworkError("directory visibility is unsupported")

    def to_dict(self) -> dict[str, Any]:
        return {"publisher_id": self.publisher_id, "head_digest": self.head_digest, "endpoint": self.endpoint, "visibility": self.visibility}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DirectoryEntry":
        value = _strict(value, {"publisher_id", "head_digest", "endpoint", "visibility"}, "directory entry")
        return _canonical_record(value, cls(**value), "directory entry")


@dataclass(frozen=True)
class SignedDirectorySnapshot:
    """Append-only signed discovery view; never a validity or reputation result."""

    directory_publisher_id: str
    sequence: int
    previous_snapshot_digest: str | None
    entries: tuple[DirectoryEntry, ...]
    issued_at: str
    public_key_base64url: str
    signature_base64url: str
    schema_version: str = DIRECTORY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != DIRECTORY_SCHEMA or not _PUBLISHER.fullmatch(self.directory_publisher_id):
            raise NetworkError("invalid directory snapshot schema or publisher")
        if type(self.sequence) is not int or not 0 <= self.sequence <= 2**53 - 1:
            raise NetworkError("directory sequence must be nonnegative")
        if self.previous_snapshot_digest is not None:
            _digest(self.previous_snapshot_digest, "previous_snapshot_digest")
        entries = tuple(sorted(self.entries, key=lambda item: item.publisher_id))
        if len(entries) != len(set(item.publisher_id for item in entries)):
            raise NetworkError("directory contains duplicate publishers")
        object.__setattr__(self, "entries", entries)
        _text(self.issued_at, "issued_at", maximum=64)
        raw = _canonical_b64(self.public_key_base64url, 32, "public_key_base64url")
        if self.directory_publisher_id != "publisher:" + digest_bytes(raw):
            raise NetworkError("directory publisher does not derive from its signing key")
        _canonical_b64(self.signature_base64url, 64, "signature_base64url")

    def signing_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "directory_publisher_id": self.directory_publisher_id, "sequence": self.sequence, "previous_snapshot_digest": self.previous_snapshot_digest, "entries": [item.to_dict() for item in self.entries], "issued_at": self.issued_at, "public_key_base64url": self.public_key_base64url}

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_dict(), "signature_base64url": self.signature_base64url}

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedDirectorySnapshot":
        value = _strict(value, {"schema_version", "directory_publisher_id", "sequence", "previous_snapshot_digest", "entries", "issued_at", "public_key_base64url", "signature_base64url"}, "directory snapshot")
        return _canonical_record(
            value, cls(value["directory_publisher_id"], value["sequence"], value["previous_snapshot_digest"], tuple(DirectoryEntry.from_dict(item) for item in _array(value["entries"], "directory entries")), value["issued_at"], value["public_key_base64url"], value["signature_base64url"], value["schema_version"]),
            "directory snapshot",
        )


def _crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:
        raise NetworkError("Ed25519 operations require verifier-standard[seal]") from exc
    return InvalidSignature, serialization, (Ed25519PrivateKey, Ed25519PublicKey)


def publisher_from_private_key(private_key_path: str | Path, display_name: str, description: str) -> PublisherRecord:
    _, serialization, (PrivateKey, _) = _crypto()
    key = serialization.load_pem_private_key(_read_bounded_regular(private_key_path, MAX_PRIVATE_KEY_BYTES, "publisher private key"), password=None)
    if not isinstance(key, PrivateKey):
        raise NetworkError("publisher private key must use Ed25519")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    encoded = _base64url_encode(raw)
    return PublisherRecord("publisher:" + digest_bytes(raw), encoded, (digest_bytes(raw),), (), display_name, description)


def sign_head(commit: SiloCommit, private_key_path: str | Path, sequence: int,
              previous_head_digest: str | None, issued_at: str) -> SignedHead:
    _, serialization, (PrivateKey, _) = _crypto()
    key = serialization.load_pem_private_key(_read_bounded_regular(private_key_path, MAX_PRIVATE_KEY_BYTES, "publisher private key"), password=None)
    if not isinstance(key, PrivateKey):
        raise NetworkError("publisher private key must use Ed25519")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    unsigned = {"schema_version": HEAD_SCHEMA, "publisher_id": commit.publisher_id, "sequence": sequence, "commit_digest": commit.canonical_digest(), "previous_head_digest": previous_head_digest, "key_id": digest_bytes(raw), "issued_at": issued_at, "public_key_base64url": _base64url_encode(raw)}
    signature = key.sign(canonical_bytes(unsigned))
    return SignedHead(
        publisher_id=commit.publisher_id,
        sequence=sequence,
        commit_digest=commit.canonical_digest(),
        previous_head_digest=previous_head_digest,
        key_id=digest_bytes(raw),
        issued_at=issued_at,
        public_key_base64url=_base64url_encode(raw),
        signature_base64url=_base64url_encode(signature),
        schema_version=HEAD_SCHEMA,
    )


def verify_head(head: SignedHead, publisher: PublisherRecord) -> None:
    InvalidSignature, _, (_, PublicKey) = _crypto()
    if head.publisher_id != publisher.publisher_id or head.key_id not in publisher.active_key_ids:
        raise NetworkError("head key is not active for its publisher")
    try:
        PublicKey.from_public_bytes(_canonical_b64(head.public_key_base64url, 32, "public_key_base64url")).verify(_canonical_b64(head.signature_base64url, 64, "signature_base64url"), canonical_bytes(head.signing_dict()))
    except InvalidSignature as exc:
        raise NetworkError("signed head signature did not verify") from exc


def create_key_continuity(publisher_id: str, previous_private_key_path: str | Path,
                          new_private_key_path: str | Path, sequence: int,
                          previous_record_digest: str | None = None) -> KeyContinuityRecord:
    _, serialization, (PrivateKey, _) = _crypto()
    old = serialization.load_pem_private_key(_read_bounded_regular(previous_private_key_path, MAX_PRIVATE_KEY_BYTES, "previous private key"), password=None)
    new = serialization.load_pem_private_key(_read_bounded_regular(new_private_key_path, MAX_PRIVATE_KEY_BYTES, "new private key"), password=None)
    if not isinstance(old, PrivateKey) or not isinstance(new, PrivateKey):
        raise NetworkError("continuity keys must use Ed25519")
    def raw(key: Any) -> bytes:
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    unsigned = {"schema_version": KEY_CONTINUITY_SCHEMA, "publisher_id": publisher_id, "previous_key_base64url": _base64url_encode(raw(old)), "new_key_base64url": _base64url_encode(raw(new)), "sequence": sequence, "previous_record_digest": previous_record_digest}
    payload = canonical_bytes(unsigned)
    return KeyContinuityRecord(
        publisher_id=publisher_id,
        previous_key_base64url=_base64url_encode(raw(old)),
        new_key_base64url=_base64url_encode(raw(new)),
        sequence=sequence,
        previous_record_digest=previous_record_digest,
        old_signature_base64url=_base64url_encode(old.sign(payload)),
        new_signature_base64url=_base64url_encode(new.sign(payload)),
        schema_version=KEY_CONTINUITY_SCHEMA,
    )


def verify_key_continuity(record: KeyContinuityRecord, expected_previous_key_id: str) -> str:
    InvalidSignature, _, (_, PublicKey) = _crypto()
    old_raw = _canonical_b64(record.previous_key_base64url, 32, "previous_key_base64url")
    new_raw = _canonical_b64(record.new_key_base64url, 32, "new_key_base64url")
    if digest_bytes(old_raw) != expected_previous_key_id:
        raise NetworkError("continuity record does not start from the expected active key")
    payload = canonical_bytes(record.signing_dict())
    try:
        PublicKey.from_public_bytes(old_raw).verify(_canonical_b64(record.old_signature_base64url, 64, "old_signature_base64url"), payload)
        PublicKey.from_public_bytes(new_raw).verify(_canonical_b64(record.new_signature_base64url, 64, "new_signature_base64url"), payload)
    except InvalidSignature as exc:
        raise NetworkError("key continuity requires valid old-key and new-key signatures") from exc
    return digest_bytes(new_raw)


def sign_directory_snapshot(entries: Sequence[DirectoryEntry], private_key_path: str | Path,
                            sequence: int, previous_snapshot_digest: str | None,
                            issued_at: str) -> SignedDirectorySnapshot:
    _, serialization, (PrivateKey, _) = _crypto()
    key = serialization.load_pem_private_key(_read_bounded_regular(private_key_path, MAX_PRIVATE_KEY_BYTES, "directory private key"), password=None)
    if not isinstance(key, PrivateKey):
        raise NetworkError("directory private key must use Ed25519")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    provisional = SignedDirectorySnapshot(
        directory_publisher_id="publisher:" + digest_bytes(raw),
        sequence=sequence,
        previous_snapshot_digest=previous_snapshot_digest,
        entries=tuple(entries),
        issued_at=issued_at,
        public_key_base64url=_base64url_encode(raw),
        signature_base64url=_base64url_encode(b"\0" * 64),
        schema_version=DIRECTORY_SCHEMA,
    )
    return SignedDirectorySnapshot(
        directory_publisher_id=provisional.directory_publisher_id,
        sequence=sequence,
        previous_snapshot_digest=previous_snapshot_digest,
        entries=tuple(entries),
        issued_at=issued_at,
        public_key_base64url=_base64url_encode(raw),
        signature_base64url=_base64url_encode(key.sign(canonical_bytes(provisional.signing_dict()))),
        schema_version=DIRECTORY_SCHEMA,
    )


def verify_directory_snapshot(snapshot: SignedDirectorySnapshot) -> None:
    InvalidSignature, _, (_, PublicKey) = _crypto()
    try:
        PublicKey.from_public_bytes(_canonical_b64(snapshot.public_key_base64url, 32, "public_key_base64url")).verify(_canonical_b64(snapshot.signature_base64url, 64, "signature_base64url"), canonical_bytes(snapshot.signing_dict()))
    except InvalidSignature as exc:
        raise NetworkError("directory snapshot signature did not verify") from exc


@dataclass(frozen=True)
class SiloAssessment:
    reconstructibility: str
    derivation_closure: str
    self_derivability: str
    completeness: str
    completeness_kind: str
    silo_grounding: str
    authority_axiom_agency: str
    reasons: tuple[str, ...]
    schema_version: str = ASSESSMENT_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "reconstructibility": self.reconstructibility, "derivation_closure": self.derivation_closure, "self_derivability": self.self_derivability, "completeness": self.completeness, "completeness_kind": self.completeness_kind, "silo_grounding": self.silo_grounding, "authority_axiom_agency": self.authority_axiom_agency, "reasons": list(self.reasons), "claim_boundary": "Results cover exact bytes, declared formation paths, the explicit census denominator, authority-model grounding, and declared action permissions only. Silo grounding does not establish preservation of allowable actions. Allowability does not establish access, capability, awareness, or non-inferability. Results do not establish artifact correctness or real-world identity."}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloAssessment":
        fields = {"schema_version", "reconstructibility", "derivation_closure", "self_derivability", "completeness", "completeness_kind", "silo_grounding", "authority_axiom_agency", "reasons", "claim_boundary"}
        value = _strict(value, fields, "silo assessment")
        if value["schema_version"] != ASSESSMENT_SCHEMA:
            raise NetworkError("unsupported silo assessment schema_version")
        if value["reconstructibility"] not in {"COMPLETE", "INCOMPLETE"}:
            raise NetworkError("unsupported reconstructibility result")
        if value["derivation_closure"] not in {"CLOSED", "OPEN"}:
            raise NetworkError("unsupported derivation_closure result")
        if value["self_derivability"] not in {"ESTABLISHED", "NOT_ESTABLISHED"}:
            raise NetworkError("unsupported self_derivability result")
        if value["completeness"] not in {"COMPLETE", "INCOMPLETE", "UNKNOWN"}:
            raise NetworkError("unsupported completeness result")
        if value["completeness_kind"] not in {"SILO_CENSUS", "DERIVATIONAL_COVERAGE", "SEMANTIC_COVERAGE", "LOGICAL_DECIDABILITY"}:
            raise NetworkError("unsupported completeness_kind")
        if value["silo_grounding"] not in {"ESTABLISHED", "NOT_ESTABLISHED", "UNKNOWN"}:
            raise NetworkError("unsupported silo_grounding result")
        if value["authority_axiom_agency"] not in {"PRESERVED", "VIOLATED", "UNKNOWN"}:
            raise NetworkError("unsupported authority_axiom_agency result")
        record = cls(
            reconstructibility=value["reconstructibility"],
            derivation_closure=value["derivation_closure"],
            self_derivability=value["self_derivability"],
            completeness=value["completeness"],
            completeness_kind=value["completeness_kind"],
            silo_grounding=value["silo_grounding"],
            authority_axiom_agency=value["authority_axiom_agency"],
            reasons=tuple(_text(item, "assessment reason") for item in _array(value["reasons"], "assessment reasons")),
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "silo assessment")


@dataclass(frozen=True)
class SiloAssessmentReceipt:
    """Non-circular binding from a commit to one checking mechanism and result."""

    commit_digest: str
    mechanism_digest: str
    assessment: SiloAssessment
    schema_version: str = ASSESSMENT_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ASSESSMENT_RECEIPT_SCHEMA:
            raise NetworkError("unsupported assessment receipt schema_version")
        _digest(self.commit_digest, "commit_digest")
        _digest(self.mechanism_digest, "mechanism_digest")
        if not isinstance(self.assessment, SiloAssessment):
            raise NetworkError("assessment receipt requires a computed SiloAssessment")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "commit_digest": self.commit_digest, "mechanism_digest": self.mechanism_digest, "assessment": self.assessment.to_dict()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloAssessmentReceipt":
        value = _strict(value, {"schema_version", "commit_digest", "mechanism_digest", "assessment"}, "silo assessment receipt")
        record = cls(
            commit_digest=value["commit_digest"],
            mechanism_digest=value["mechanism_digest"],
            assessment=SiloAssessment.from_dict(value["assessment"]),
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "silo assessment receipt")

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class SiloComposition:
    """Canonical declaration of exact member commits and optional composite."""

    member_commit_digests: tuple[str, ...]
    composite_commit_digest: str | None = None
    schema_version: str = COMPOSITION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMPOSITION_SCHEMA:
            raise NetworkError("unsupported silo composition schema_version")
        if not self.member_commit_digests or len(self.member_commit_digests) > MAX_ENTRIES:
            raise NetworkError("composition must declare one to 256 member commits")
        object.__setattr__(self, "member_commit_digests", _unique((_digest(item, "member commit digest") for item in self.member_commit_digests), "member_commit_digests"))
        if self.composite_commit_digest is not None:
            _digest(self.composite_commit_digest, "composite_commit_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "member_commit_digests": list(self.member_commit_digests),
            "composite_commit_digest": self.composite_commit_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloComposition":
        value = _strict(value, {"schema_version", "member_commit_digests", "composite_commit_digest"}, "silo composition")
        record = cls(
            member_commit_digests=tuple(_array(value["member_commit_digests"], "member_commit_digests", MAX_ENTRIES)),
            composite_commit_digest=value["composite_commit_digest"],
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "silo composition")

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


_COMPOSITION_CLAIM_BOUNDARY = "Authority axiom agency is a ground-level floor evaluated over exact declared finite reachable states, never an intersection with local restrictions. Silo grounding establishes only the exact authority-model grounding prerequisites and remains independent from action preservation. Composition-preserved local additions remain separate from ground agency. Member completeness does not imply composition completeness: the composite is itself an independently assessed silo containing exact member commits, bridges, adapters, relations, policies, and residual obligations. Composition fails closed if any required boundary is absent; it does not infer actual runtime behavior, truth, or merge conflicting claims."


@dataclass(frozen=True)
class SiloCompositionAssessment:
    """Typed result of the existing reference composition assessor."""

    result: str
    composition_completeness: str
    composition_member_binding: str
    local_authority_addition_preservation: str
    authority_axiom_agency: str
    effective_authority_axiom_agency: tuple[str, ...]
    silos: tuple[SiloAssessment, ...]
    composite_silo: SiloAssessment | None
    schema_version: str = COMPOSITION_ASSESSMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMPOSITION_ASSESSMENT_SCHEMA:
            raise NetworkError("unsupported silo composition assessment schema_version")
        if self.result not in {"ADMISSIBLE", "NOT_ADMISSIBLE"}:
            raise NetworkError("unsupported composition result")
        if self.composition_completeness not in {"COMPLETE", "INCOMPLETE", "UNKNOWN"}:
            raise NetworkError("unsupported composition completeness result")
        if self.composition_member_binding not in {"COMPLETE", "INCOMPLETE", "UNKNOWN"}:
            raise NetworkError("unsupported composition member binding result")
        if self.local_authority_addition_preservation not in {"COMPLETE", "INCOMPLETE", "UNKNOWN"}:
            raise NetworkError("unsupported local authority addition preservation result")
        if self.authority_axiom_agency not in {"PRESERVED", "VIOLATED", "UNKNOWN"}:
            raise NetworkError("unsupported composition authority result")
        if not self.silos or not all(isinstance(item, SiloAssessment) for item in self.silos):
            raise NetworkError("composition assessment requires member silo assessments")
        if self.composite_silo is not None and not isinstance(self.composite_silo, SiloAssessment):
            raise NetworkError("composite_silo must be a silo assessment or null")
        object.__setattr__(self, "effective_authority_axiom_agency", _unique((_text(item, "effective authority action", maximum=128) for item in self.effective_authority_axiom_agency), "effective_authority_axiom_agency"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "result": self.result,
            "composition_completeness": self.composition_completeness,
            "composition_member_binding": self.composition_member_binding,
            "local_authority_addition_preservation": self.local_authority_addition_preservation,
            "authority_axiom_agency": self.authority_axiom_agency,
            "effective_authority_axiom_agency": list(self.effective_authority_axiom_agency),
            "silos": [item.to_dict() for item in self.silos],
            "composite_silo": None if self.composite_silo is None else self.composite_silo.to_dict(),
            "claim_boundary": _COMPOSITION_CLAIM_BOUNDARY,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloCompositionAssessment":
        fields = {"schema_version", "result", "composition_completeness", "composition_member_binding", "local_authority_addition_preservation", "authority_axiom_agency", "effective_authority_axiom_agency", "silos", "composite_silo", "claim_boundary"}
        value = _strict(value, fields, "silo composition assessment")
        record = cls(
            result=value["result"],
            composition_completeness=value["composition_completeness"],
            composition_member_binding=value["composition_member_binding"],
            local_authority_addition_preservation=value["local_authority_addition_preservation"],
            authority_axiom_agency=value["authority_axiom_agency"],
            effective_authority_axiom_agency=tuple(_array(value["effective_authority_axiom_agency"], "effective_authority_axiom_agency")),
            silos=tuple(SiloAssessment.from_dict(item) for item in _array(value["silos"], "silos", MAX_ENTRIES)),
            composite_silo=None if value["composite_silo"] is None else SiloAssessment.from_dict(value["composite_silo"]),
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "silo composition assessment")


@dataclass(frozen=True)
class SiloCompositionAssessmentReceipt:
    """Bind a composition declaration, mechanism, nested receipts, and result."""

    declaration_digest: str
    composition_mechanism_digest: str
    member_assessment_receipts: tuple[SiloAssessmentReceipt, ...]
    composite_assessment_receipt: SiloAssessmentReceipt | None
    assessment: SiloCompositionAssessment
    schema_version: str = COMPOSITION_ASSESSMENT_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMPOSITION_ASSESSMENT_RECEIPT_SCHEMA:
            raise NetworkError("unsupported silo composition assessment receipt schema_version")
        _digest(self.declaration_digest, "declaration_digest")
        _digest(self.composition_mechanism_digest, "composition_mechanism_digest")
        if (
            not self.member_assessment_receipts
            or len(self.member_assessment_receipts) > MAX_ENTRIES
            or not all(isinstance(item, SiloAssessmentReceipt) for item in self.member_assessment_receipts)
        ):
            raise NetworkError("composition receipt requires member assessment receipts")
        member_digests = tuple(item.commit_digest for item in self.member_assessment_receipts)
        if member_digests != tuple(sorted(member_digests)) or len(member_digests) != len(set(member_digests)):
            raise NetworkError("member assessment receipts must use canonical unique commit order")
        if self.composite_assessment_receipt is not None and not isinstance(self.composite_assessment_receipt, SiloAssessmentReceipt):
            raise NetworkError("composite assessment receipt must be a silo assessment receipt or null")
        if not isinstance(self.assessment, SiloCompositionAssessment):
            raise NetworkError("composition receipt requires a computed composition assessment")
        if len(self.member_assessment_receipts) != len(self.assessment.silos):
            raise NetworkError("member receipts and composition member assessments must have equal length")
        if any(
            receipt.assessment != assessment
            for receipt, assessment in zip(self.member_assessment_receipts, self.assessment.silos)
        ):
            raise NetworkError("member receipts must exactly bind the ordered composition member assessments")
        if (self.composite_assessment_receipt is None) != (self.assessment.composite_silo is None):
            raise NetworkError("composite receipt presence must match the composition assessment")
        if (
            self.composite_assessment_receipt is not None
            and self.composite_assessment_receipt.assessment != self.assessment.composite_silo
        ):
            raise NetworkError("composite receipt must exactly bind the composition composite assessment")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "declaration_digest": self.declaration_digest,
            "composition_mechanism_digest": self.composition_mechanism_digest,
            "member_assessment_receipts": [item.to_dict() for item in self.member_assessment_receipts],
            "composite_assessment_receipt": None if self.composite_assessment_receipt is None else self.composite_assessment_receipt.to_dict(),
            "assessment": self.assessment.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SiloCompositionAssessmentReceipt":
        fields = {"schema_version", "declaration_digest", "composition_mechanism_digest", "member_assessment_receipts", "composite_assessment_receipt", "assessment"}
        value = _strict(value, fields, "silo composition assessment receipt")
        record = cls(
            declaration_digest=value["declaration_digest"],
            composition_mechanism_digest=value["composition_mechanism_digest"],
            member_assessment_receipts=tuple(SiloAssessmentReceipt.from_dict(item) for item in _array(value["member_assessment_receipts"], "member_assessment_receipts", MAX_ENTRIES)),
            composite_assessment_receipt=None if value["composite_assessment_receipt"] is None else SiloAssessmentReceipt.from_dict(value["composite_assessment_receipt"]),
            assessment=SiloCompositionAssessment.from_dict(value["assessment"]),
            schema_version=value["schema_version"],
        )
        return _canonical_record(value, record, "silo composition assessment receipt")

    def canonical_digest(self) -> str:
        return digest_bytes(canonical_bytes(self.to_dict()))


class ContentAddressedStore:
    """Non-overwriting local store whose indexes are reconstructible caches."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("objects/sha256", "records/commits", "records/heads", "records/publishers", "records/keys", "records/directories", "records/assessments"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def _object_path(self, digest: str) -> Path:
        return self.root / "objects" / "sha256" / _digest(digest).split(":", 1)[1]

    def add_object(self, payload: bytes, media_type: str, artifact_kind: str, declared_schema_id: str = "NOT_DECLARED") -> ObjectRecord:
        record = ObjectRecord.from_payload(payload, media_type, artifact_kind, declared_schema_id)
        self.initialize()
        path = self._object_path(record.object_digest)
        if path.exists():
            if _read_bounded_regular(path, MAX_OBJECT_BYTES, "existing object") != payload:
                raise NetworkError("existing object path contains different bytes")
        else:
            with path.open("xb") as stream:
                stream.write(payload)
        return record

    def read_object(self, record: ObjectRecord) -> bytes:
        try:
            path = self._object_path(record.object_digest)
            data = _read_bounded_regular(path, MAX_OBJECT_BYTES, "object storage entry")
        except (OSError, NetworkError) as exc:
            raise NetworkError("object bytes are unavailable") from exc
        if len(data) != record.size_bytes or digest_bytes(data) != record.object_digest:
            raise NetworkError("object bytes do not match the census record")
        return data

    def put_record(self, kind: str, value: Mapping[str, Any]) -> str:
        if kind not in {"commits", "heads", "publishers", "keys", "directories", "assessments"}:
            raise NetworkError("unsupported record kind")
        self.initialize()
        data = canonical_bytes(value)
        if len(data) > MAX_RECORD_BYTES:
            raise NetworkError("content-addressed record exceeds its byte bound")
        digest = digest_bytes(data)
        path = self.root / "records" / kind / (digest.split(":", 1)[1] + ".json")
        if path.exists() and _read_bounded_regular(path, MAX_RECORD_BYTES, "existing record") != data:
            raise NetworkError("existing record path contains different bytes")
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(data)
        return digest

    def read_record(self, kind: str, digest: str) -> Mapping[str, Any]:
        if kind not in {"commits", "heads", "publishers", "keys", "directories", "assessments"}:
            raise NetworkError("unsupported record kind")
        path = self.root / "records" / kind / (_digest(digest).split(":", 1)[1] + ".json")
        try:
            data = _read_bounded_regular(path, MAX_RECORD_BYTES, "content-addressed record")
            value = json.loads(data)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise NetworkError("content-addressed record is unavailable or malformed") from exc
        if digest_bytes(data) != digest or not isinstance(value, Mapping) or canonical_bytes(value) != data:
            raise NetworkError("content-addressed record does not match its digest or canonical form")
        return value


def _load_authority_model(commit: SiloCommit, store: ContentAddressedStore) -> AuthorityModel | None:
    if commit.authority_model_path is None:
        return None
    entries = {entry.path: entry for entry in commit.census}
    entry = entries[commit.authority_model_path]
    if (
        entry.object_record.artifact_kind != "authority-model"
        or entry.object_record.declared_schema_id != AUTHORITY_MODEL_SCHEMA
        or entry.object_record.media_type != "application/json"
    ):
        raise NetworkError("authority model path must retain the registered canonical authority-model artifact")
    raw = store.read_object(entry.object_record)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NetworkError("authority model artifact is not canonical JSON") from exc
    model = AuthorityModel.from_dict(value)
    if canonical_bytes(model.to_dict()) != raw:
        raise NetworkError("authority model artifact is not canonical JSON")
    return model


def _assess_authority_model(
    commit: SiloCommit,
    model: AuthorityModel | None,
    derived: set[str],
    necessary: set[str],
) -> tuple[str, tuple[str, ...], frozenset[str]]:
    """Interpret one exact finite model; no actual-runtime behavior is inferred."""

    reasons: list[str] = []
    preserved: set[str] = set()
    binding_exact = (
        commit.authority_axiom_agency_version == AUTHORITY_AXIOM_AGENCY_VERSION
        and commit.authority_axiom_agency_digest == authority_axiom_agency_digest(commit.authority_axiom_agency)
    )
    if not binding_exact:
        return "UNKNOWN", ("authority axiom agency version or digest is not the canonical alpha binding",), frozenset()
    if commit.authority_axiom_agency != AUTHORITY_AXIOM_AGENCY:
        if set(AUTHORITY_AXIOM_AGENCY) <= set(commit.authority_axiom_agency):
            return "UNKNOWN", ("authority axiom agency contains an unsupported local extension",), frozenset()
        return "VIOLATED", ("declared authority axiom agency omits required actions",), frozenset()
    if model is None:
        return "UNKNOWN", ("exact static ground binding does not establish preservation over reachable states",), frozenset()
    if commit.authority_model_path not in necessary or commit.authority_model_path not in derived:
        return "UNKNOWN", ("authority model must be a necessary ground-reachable census artifact",), frozenset()
    if (
        model.authority_axiom_agency_version != AUTHORITY_AXIOM_AGENCY_VERSION
        or model.authority_axiom_agency_digest != authority_axiom_agency_digest()
        or model.actor_scope_version != AUTHORITY_ACTOR_SCOPE_VERSION
        or model.actor_scope_digest != authority_actor_scope_digest()
    ):
        return "UNKNOWN", ("authority model ground or actor-scope binding is unsupported",), frozenset()
    state_ids = {item.state_id for item in model.states}
    transition_ids = {item.transition_id for item in model.transitions}
    if set(model.state_universe) != state_ids or set(model.transition_universe) != transition_ids:
        return "UNKNOWN", ("authority model universes do not exactly enumerate their records",), frozenset()
    if not model.initial_state_ids or not set(model.initial_state_ids) <= state_ids:
        return "UNKNOWN", ("authority model initial states are absent or outside the declared universe",), frozenset()
    for transition in model.transitions:
        if transition.source_state_id not in state_ids or transition.target_state_id not in state_ids or transition.actor_scope not in AUTHORITY_ACTOR_SCOPES:
            return "UNKNOWN", ("authority transition endpoints or actor scope are unsupported",), frozenset()
    if any(
        addition.actor_scope not in AUTHORITY_ACTOR_SCOPES
        for state in model.states
        for addition in state.local_authority_additions
    ):
        return "UNKNOWN", ("local authority addition uses an unsupported actor scope",), frozenset()
    reachable = set(model.initial_state_ids)
    progress = True
    while progress:
        progress = False
        for transition in model.transitions:
            if transition.source_state_id in reachable and transition.target_state_id not in reachable:
                reachable.add(transition.target_state_id)
                progress = True
    # A bound reachable counterexample needs no claim that the positive state
    # denominator is closed. Never use an unvalidated edge or unreachable state.
    for state in model.states:
        if state.state_id in reachable and not set(AUTHORITY_AXIOM_AGENCY) <= set(state.ground_actions):
            return "VIOLATED", (f"reachable authority state {state.state_id} removes a ground action",), frozenset()
    if reachable != state_ids:
        return "UNKNOWN", ("authority state universe is not the exact reachable closure",), frozenset()
    if model.closure_status != "CLOSED" or model.residual_obligations:
        return "UNKNOWN", ("authority transition closure is open or has residual obligations",), frozenset()
    unknown_ground_extension = False
    for state in model.states:
        ground = set(state.ground_actions)
        if ground != set(AUTHORITY_AXIOM_AGENCY):
            unknown_ground_extension = True
        for addition in state.local_authority_additions:
            if addition.propagation == "COMPOSITION_PRESERVED":
                preserved.add(addition.canonical_digest())
    if unknown_ground_extension:
        reasons.append("reachable authority state places a local extension in the ground action set")
        return "UNKNOWN", tuple(reasons), frozenset(preserved)
    return "PRESERVED", (), frozenset(preserved)


def _assess_silo_grounding(
    commit: SiloCommit,
    model: AuthorityModel | None,
    derived: set[str],
    necessary: set[str],
) -> tuple[str, tuple[str, ...]]:
    """Assess the exact finite authority model's grounding, not its action floor."""

    binding_exact = (
        commit.authority_axiom_agency_version == AUTHORITY_AXIOM_AGENCY_VERSION
        and commit.authority_axiom_agency_digest
        == authority_axiom_agency_digest(commit.authority_axiom_agency)
        and commit.authority_axiom_agency == AUTHORITY_AXIOM_AGENCY
    )
    if not binding_exact:
        return "UNKNOWN", (
            "silo grounding requires the exact canonical agency version, digest, and action-set identity",
        )
    if model is None:
        return "UNKNOWN", (
            "silo grounding requires a present canonical authority model",
        )
    if commit.authority_model_path not in necessary or commit.authority_model_path not in derived:
        return "NOT_ESTABLISHED", (
            "silo grounding requires the authority model to be necessary and ground-reachable",
        )
    if (
        model.authority_axiom_agency_version != AUTHORITY_AXIOM_AGENCY_VERSION
        or model.authority_axiom_agency_digest != authority_axiom_agency_digest()
        or model.actor_scope_version != AUTHORITY_ACTOR_SCOPE_VERSION
        or model.actor_scope_digest != authority_actor_scope_digest()
    ):
        return "UNKNOWN", (
            "silo grounding authority or actor-scope binding is unsupported",
        )
    state_ids = {item.state_id for item in model.states}
    transition_ids = {item.transition_id for item in model.transitions}
    if set(model.state_universe) != state_ids or set(model.transition_universe) != transition_ids:
        return "NOT_ESTABLISHED", (
            "silo grounding universes do not exactly enumerate the finite authority records",
        )
    if not model.initial_state_ids or not set(model.initial_state_ids) <= state_ids:
        return "NOT_ESTABLISHED", (
            "silo grounding initial states are absent or outside the declared state universe",
        )
    if any(
        transition.source_state_id not in state_ids
        or transition.target_state_id not in state_ids
        or transition.actor_scope not in AUTHORITY_ACTOR_SCOPES
        for transition in model.transitions
    ):
        return "NOT_ESTABLISHED", (
            "silo grounding transition endpoints or actor scopes are outside the supported universes",
        )
    if any(
        addition.actor_scope not in AUTHORITY_ACTOR_SCOPES
        for state in model.states
        for addition in state.local_authority_additions
    ):
        return "UNKNOWN", (
            "silo grounding local authority actor-scope binding is unsupported",
        )
    reachable = set(model.initial_state_ids)
    progress = True
    while progress:
        progress = False
        for transition in model.transitions:
            if transition.source_state_id in reachable and transition.target_state_id not in reachable:
                reachable.add(transition.target_state_id)
                progress = True
    if reachable != state_ids:
        return "NOT_ESTABLISHED", (
            "silo grounding state universe is not the exact reachable closure",
        )
    if model.closure_status != "CLOSED" or model.residual_obligations:
        return "NOT_ESTABLISHED", (
            "silo grounding authority transition closure is open or has residual obligations",
        )
    return "ESTABLISHED", ()


def _authority_surface_completeness(
    commit: SiloCommit,
    model: AuthorityModel | None,
    derived: set[str],
    necessary: set[str],
) -> str:
    """Classify only whether the declared authority surface has a closed census.

    This is independent from whether a fully enumerated reachable state violates
    the authority floor.  An absent required surface leaves the denominator
    unknown; a present but structurally incomplete surface is known incomplete.
    """

    if commit.authority_model_path is None:
        return "UNKNOWN"
    if model is None:
        return "INCOMPLETE"
    if commit.authority_model_path not in necessary or commit.authority_model_path not in derived:
        return "INCOMPLETE"
    if (
        model.authority_axiom_agency_version != AUTHORITY_AXIOM_AGENCY_VERSION
        or model.authority_axiom_agency_digest != authority_axiom_agency_digest()
        or model.actor_scope_version != AUTHORITY_ACTOR_SCOPE_VERSION
        or model.actor_scope_digest != authority_actor_scope_digest()
    ):
        return "INCOMPLETE"
    state_ids = {item.state_id for item in model.states}
    transition_ids = {item.transition_id for item in model.transitions}
    if set(model.state_universe) != state_ids or set(model.transition_universe) != transition_ids:
        return "INCOMPLETE"
    if not model.initial_state_ids or not set(model.initial_state_ids) <= state_ids:
        return "INCOMPLETE"
    if any(
        transition.source_state_id not in state_ids
        or transition.target_state_id not in state_ids
        or transition.actor_scope not in AUTHORITY_ACTOR_SCOPES
        for transition in model.transitions
    ):
        return "INCOMPLETE"
    reachable = set(model.initial_state_ids)
    progress = True
    while progress:
        progress = False
        for transition in model.transitions:
            if transition.source_state_id in reachable and transition.target_state_id not in reachable:
                reachable.add(transition.target_state_id)
                progress = True
    if reachable != state_ids:
        return "INCOMPLETE"
    if model.closure_status != "CLOSED" or model.residual_obligations:
        return "INCOMPLETE"
    if any(
        addition.actor_scope not in AUTHORITY_ACTOR_SCOPES
        for state in model.states
        for addition in state.local_authority_additions
    ):
        return "INCOMPLETE"
    return "COMPLETE"


def assess_silo(commit: SiloCommit, store: ContentAddressedStore) -> SiloAssessment:
    reasons: list[str] = []
    missing: set[str] = set()
    for entry in commit.census:
        try:
            store.read_object(entry.object_record)
        except NetworkError:
            missing.add(entry.path)
    reconstructibility = "COMPLETE" if not missing else "INCOMPLETE"
    if missing:
        reasons.append("missing or mismatched object bytes: " + ", ".join(sorted(missing)))

    known = {entry.path for entry in commit.census}
    necessary = {entry.path for entry in commit.census if entry.necessity == "NECESSARY"}
    derived = set(commit.ground_paths)
    edges = list(commit.derivations)
    progress = True
    while progress:
        progress = False
        for edge in edges:
            if edge.mechanism_path in derived and edge.mechanism_path in necessary and set(edge.premise_paths) <= derived and edge.target_path not in derived:
                derived.add(edge.target_path)
                progress = True
    open_paths = necessary - derived
    derivation_closure = "CLOSED" if not open_paths else "OPEN"
    if open_paths:
        reasons.append("necessary census paths lack a ground-reachable derivation: " + ", ".join(sorted(open_paths)))
    authority_model: AuthorityModel | None = None
    if commit.authority_model_path is not None:
        try:
            authority_model = _load_authority_model(commit, store)
        except NetworkError as exc:
            reasons.append(str(exc))
    authority_surface_completeness = _authority_surface_completeness(
        commit, authority_model, derived, necessary
    )
    if authority_surface_completeness == "UNKNOWN":
        reasons.append("required authority surface is absent, so its completeness denominator is unknown")
    elif authority_surface_completeness == "INCOMPLETE":
        reasons.append("declared authority surface is not a complete closed census")
    expected_boundary = census_boundary_members(
        commit.census, commit.ground_paths, commit.derivations, commit.relations,
        commit.authority_axiom_agency, commit.residual_obligations, commit.exclusions,
        publisher_id=commit.publisher_id, parents=commit.parents,
        completeness_kind=commit.completeness_kind,
        authority_version=commit.authority_axiom_agency_version,
        authority_digest=commit.authority_axiom_agency_digest,
        self_derivation_record=commit.self_derivation_record,
        created_at=commit.created_at,
        authority_model_path=commit.authority_model_path,
        authority_model=authority_model,
    )
    census_covers_universe = bool(commit.coverage_universe) and commit.coverage_universe == expected_boundary
    if not census_covers_universe:
        reasons.append("coverage_universe does not exactly enumerate the typed census boundary")
    if commit.completeness_kind == "SILO_CENSUS":
        known_incomplete = (
            reconstructibility != "COMPLETE"
            or derivation_closure != "CLOSED"
            or not census_covers_universe
            or bool(commit.residual_obligations)
            or authority_surface_completeness == "INCOMPLETE"
        )
        if known_incomplete:
            completeness = "INCOMPLETE"
        elif authority_surface_completeness == "UNKNOWN":
            completeness = "UNKNOWN"
        else:
            completeness = "COMPLETE"
    elif commit.completeness_kind == "DERIVATIONAL_COVERAGE":
        completeness = "UNKNOWN"
        reasons.append("the alpha mechanism has no declared derivation universe or universal derivational-coverage proof")
    else:
        completeness = "UNKNOWN"
        reasons.append("the reference mechanism does not establish semantic coverage or logical decidability")
    if commit.residual_obligations:
        reasons.append("residual obligations remain: " + ", ".join(commit.residual_obligations))
    self_record = commit.self_derivation_record
    census_by_path = {entry.path: entry for entry in commit.census}
    try:
        mechanism_is_registered = (
            store.read_object(census_by_path[self_record.mechanism_path].object_record)
            == self_derivation_mechanism_bytes()
        )
    except NetworkError:
        mechanism_is_registered = False
    path_reachable: set[str] = set()
    retained_path_continuous = True
    for path in self_record.retained_path:
        if path in commit.ground_paths:
            path_reachable.add(path)
            continue
        candidates = [edge for edge in commit.derivations if edge.target_path == path]
        if not any(edge.mechanism_path in path_reachable and set(edge.premise_paths) <= path_reachable for edge in candidates):
            retained_path_continuous = False
            break
        path_reachable.add(path)
    retained_terminal_edge = any(
        edge.target_path == self_record.subject_path
        and edge.mechanism_path == self_record.mechanism_path
        and edge.relation_strength == self_record.relation_strength
        and set(edge.premise_paths) <= set(self_record.retained_path)
        for edge in commit.derivations
    )
    evidence_specs = (
        ("ground_self", self_record.ground_self, self_record.ground_self_evidence_path),
        ("derivation_reflexivity", self_record.derivation_reflexivity, self_record.derivation_reflexivity_evidence_path),
        ("reflexion_identity", self_record.reflexion_identity, self_record.reflexion_identity_evidence_path),
        ("deriver_cycle_closed", self_record.deriver_cycle_closed, self_record.deriver_cycle_closure_evidence_path),
    )
    evidence_valid = True
    for predicate, declared, path in evidence_specs:
        entry = census_by_path[path]
        if not declared or path not in derived or entry.object_record.artifact_kind != "self-derivation-evidence":
            evidence_valid = False
            continue
        try:
            evidence = json.loads(store.read_object(entry.object_record))
            expected = {
                "schema_version": SELF_DERIVATION_EVIDENCE_SCHEMA,
                "predicate": predicate,
                "subject_path": self_record.subject_path,
                "mechanism_digest": census_by_path[self_record.mechanism_path].object_record.object_digest,
            }
            if evidence != expected or canonical_bytes(evidence) != store.read_object(entry.object_record):
                evidence_valid = False
        except (NetworkError, UnicodeError, json.JSONDecodeError):
            evidence_valid = False
    interpreted_predicates = {
        "ground_self": (
            bool(self_record.ground_paths)
            and set(self_record.ground_paths) <= set(commit.ground_paths)
            and set(self_record.ground_paths) <= necessary
        ),
        "derivation_reflexivity": self_record.mechanism_path in necessary and self_record.mechanism_path in commit.ground_paths,
        "reflexion_identity": (
            self_record.subject_path in necessary
            and census_by_path[self_record.subject_path].object_record.artifact_kind == "self-derivation-status"
            and retained_terminal_edge
        ),
        "deriver_cycle_closed": (
            derivation_closure == "CLOSED"
            and retained_path_continuous
            and set(self_record.retained_path) <= known
            and not self_record.residual_obligations
        ),
    }
    declared_predicates = {
        "ground_self": self_record.ground_self,
        "derivation_reflexivity": self_record.derivation_reflexivity,
        "reflexion_identity": self_record.reflexion_identity,
        "deriver_cycle_closed": self_record.deriver_cycle_closed,
    }
    self_derivability = "ESTABLISHED" if (
        reconstructibility == "COMPLETE"
        and mechanism_is_registered
        and census_by_path[self_record.mechanism_path].object_record.artifact_kind == "derivation-mechanism"
        and self_record.relation_strength in SUPPORTED_RELATION_STRENGTHS
        and evidence_valid
        and all(declared_predicates.values())
        and all(interpreted_predicates.values())
    ) else "NOT_ESTABLISHED"
    if self_derivability != "ESTABLISHED":
        reasons.append("self-derivation requires the registered declarative mechanism to interpret ground-self, derivational reflexivity, reflexion identity, closed deriver cycle, retained formation path, relation strength, bound evidence, and residual obligations")
    authority_agency, authority_reasons, _preserved = _assess_authority_model(
        commit, authority_model, derived, necessary
    )
    silo_grounding, grounding_reasons = _assess_silo_grounding(
        commit, authority_model, derived, necessary
    )
    reasons.extend(grounding_reasons)
    reasons.extend(authority_reasons)
    return SiloAssessment(reconstructibility, derivation_closure, self_derivability, completeness, commit.completeness_kind, silo_grounding, authority_agency, tuple(reasons))


def build_silo_assessment_receipt(commit: SiloCommit,
                                  store: ContentAddressedStore) -> SiloAssessmentReceipt:
    """Bind a computed independent-axis result to the exact commit and retained mechanism."""

    mechanism_path = commit.self_derivation_record.mechanism_path
    mechanism = next(entry.object_record for entry in commit.census if entry.path == mechanism_path)
    return SiloAssessmentReceipt(
        commit.canonical_digest(), mechanism.object_digest, assess_silo(commit, store)
    )


def assess_composition(commits: Sequence[SiloCommit], stores: Sequence[ContentAddressedStore],
                       composite_commit: SiloCommit | None = None,
                       composite_store: ContentAddressedStore | None = None) -> dict[str, Any]:
    if not commits or len(commits) != len(stores):
        raise NetworkError("composition requires matching nonempty commit and store sequences")
    assessments = tuple(assess_silo(commit, store) for commit, store in zip(commits, stores))
    member_agencies = {item.authority_axiom_agency for item in assessments}
    agency = "VIOLATED" if "VIOLATED" in member_agencies else "PRESERVED" if member_agencies == {"PRESERVED"} else "UNKNOWN"
    composite_assessment: SiloAssessment | None = None
    member_binding = "UNKNOWN"
    local_addition_preservation = "UNKNOWN"
    if composite_commit is not None and composite_store is not None:
        composite_assessment = assess_silo(composite_commit, composite_store)
        expected_members = {commit.canonical_digest() for commit in commits}
        retained_members = {
            entry.object_record.object_digest
            for entry in composite_commit.census
            if entry.object_record.artifact_kind == "member-commit"
        }
        composite_kinds = {entry.object_record.artifact_kind for entry in composite_commit.census}
        required_composite_kinds = {
            "member-commit", "composition-adapter", "composition-policy", "composition-relation"
        }
        member_binding = "COMPLETE" if (
            retained_members == expected_members and required_composite_kinds <= composite_kinds
        ) else "INCOMPLETE"
        if all(item.authority_axiom_agency == "PRESERVED" for item in assessments) and composite_assessment.authority_axiom_agency == "PRESERVED":
            try:
                member_models = tuple(_load_authority_model(commit, store) for commit, store in zip(commits, stores))
                composite_model = _load_authority_model(composite_commit, composite_store)
                if any(item is None for item in member_models) or composite_model is None:
                    local_addition_preservation = "UNKNOWN"
                else:
                    required_additions = {
                        addition.canonical_digest()
                        for model in member_models if model is not None
                        for state in model.states
                        for addition in state.local_authority_additions
                        if addition.propagation == "COMPOSITION_PRESERVED"
                    }
                    composite_state_additions = [
                        {addition.canonical_digest() for addition in state.local_authority_additions}
                        for state in composite_model.states
                    ]
                    retained_additions = set.intersection(*composite_state_additions) if composite_state_additions else set()
                    local_addition_preservation = "COMPLETE" if required_additions <= retained_additions else "INCOMPLETE"
            except NetworkError:
                local_addition_preservation = "UNKNOWN"
    composition_completeness = "UNKNOWN" if composite_assessment is None else composite_assessment.completeness
    members_admissible = all(item.reconstructibility == "COMPLETE" and item.derivation_closure == "CLOSED" and item.self_derivability == "ESTABLISHED" and item.completeness == "COMPLETE" and item.silo_grounding == "ESTABLISHED" and item.authority_axiom_agency == "PRESERVED" for item in assessments)
    composite_admissible = composite_assessment is not None and all((composite_assessment.reconstructibility == "COMPLETE", composite_assessment.derivation_closure == "CLOSED", composite_assessment.self_derivability == "ESTABLISHED", composite_assessment.completeness == "COMPLETE", composite_assessment.silo_grounding == "ESTABLISHED", composite_assessment.authority_axiom_agency == "PRESERVED", member_binding == "COMPLETE", local_addition_preservation == "COMPLETE"))
    admissible = members_admissible and composite_admissible
    composite_agency = None if composite_assessment is None else composite_assessment.authority_axiom_agency
    composed_agency = "VIOLATED" if "VIOLATED" in {agency, composite_agency} else "PRESERVED" if agency == composite_agency == "PRESERVED" and member_binding == "COMPLETE" else "UNKNOWN"
    return {"result": "ADMISSIBLE" if admissible else "NOT_ADMISSIBLE", "composition_completeness": composition_completeness, "composition_member_binding": member_binding, "local_authority_addition_preservation": local_addition_preservation, "authority_axiom_agency": composed_agency, "effective_authority_axiom_agency": list(AUTHORITY_AXIOM_AGENCY), "silos": [item.to_dict() for item in assessments], "composite_silo": None if composite_assessment is None else composite_assessment.to_dict(), "claim_boundary": _COMPOSITION_CLAIM_BOUNDARY}


def _typed_composition_assessment(value: Mapping[str, Any]) -> SiloCompositionAssessment:
    return SiloCompositionAssessment.from_dict({
        "schema_version": COMPOSITION_ASSESSMENT_SCHEMA,
        **value,
    })


def build_silo_composition_assessment_receipt(
    declaration: SiloComposition,
    members: Sequence[tuple[SiloCommit, ContentAddressedStore]],
    composite: tuple[SiloCommit, ContentAddressedStore] | None = None,
) -> SiloCompositionAssessmentReceipt:
    """Recompute and bind the exact declared composition and nested receipts."""

    if not isinstance(declaration, SiloComposition):
        raise NetworkError("composition receipt requires a SiloComposition declaration")
    if not members:
        raise NetworkError("composition receipt requires resolved members")
    resolved: list[tuple[str, SiloCommit, ContentAddressedStore]] = []
    for item in members:
        if not isinstance(item, tuple) or len(item) != 2:
            raise NetworkError("resolved members must be (SiloCommit, ContentAddressedStore) pairs")
        commit, store = item
        if not isinstance(commit, SiloCommit) or not isinstance(store, ContentAddressedStore):
            raise NetworkError("resolved members must contain exact commits and stores")
        resolved.append((commit.canonical_digest(), commit, store))
    resolved.sort(key=lambda item: item[0])
    resolved_digests = tuple(item[0] for item in resolved)
    if resolved_digests != declaration.member_commit_digests:
        raise NetworkError("resolved member commits do not exactly match the composition declaration")

    composite_commit: SiloCommit | None = None
    composite_store: ContentAddressedStore | None = None
    if composite is not None:
        if not isinstance(composite, tuple) or len(composite) != 2:
            raise NetworkError("resolved composite must be a (SiloCommit, ContentAddressedStore) pair")
        composite_commit, composite_store = composite
        if not isinstance(composite_commit, SiloCommit) or not isinstance(composite_store, ContentAddressedStore):
            raise NetworkError("resolved composite must contain an exact commit and store")
    resolved_composite_digest = None if composite_commit is None else composite_commit.canonical_digest()
    if resolved_composite_digest != declaration.composite_commit_digest:
        raise NetworkError("resolved composite commit does not exactly match the composition declaration")

    ordered_commits = tuple(item[1] for item in resolved)
    ordered_stores = tuple(item[2] for item in resolved)
    member_receipts = tuple(
        build_silo_assessment_receipt(commit, store)
        for commit, store in zip(ordered_commits, ordered_stores)
    )
    composite_receipt = None if composite_commit is None or composite_store is None else build_silo_assessment_receipt(composite_commit, composite_store)
    assessment = _typed_composition_assessment(assess_composition(
        ordered_commits,
        ordered_stores,
        composite_commit,
        composite_store,
    ))
    return SiloCompositionAssessmentReceipt(
        declaration_digest=declaration.canonical_digest(),
        composition_mechanism_digest=digest_bytes(silo_composition_mechanism_bytes()),
        member_assessment_receipts=member_receipts,
        composite_assessment_receipt=composite_receipt,
        assessment=assessment,
    )


def recheck_silo_composition_assessment_receipt(
    declaration: SiloComposition,
    receipt: SiloCompositionAssessmentReceipt | Mapping[str, Any],
    members: Sequence[tuple[SiloCommit, ContentAddressedStore]],
    composite: tuple[SiloCommit, ContentAddressedStore] | None = None,
) -> None:
    """Reject unless a full canonical receipt equals independent recomputation."""

    supplied = receipt if isinstance(receipt, SiloCompositionAssessmentReceipt) else SiloCompositionAssessmentReceipt.from_dict(receipt)
    expected = build_silo_composition_assessment_receipt(declaration, members, composite)
    if canonical_bytes(supplied.to_dict()) != canonical_bytes(expected.to_dict()):
        raise NetworkError("composition assessment receipt does not match independent recomputation")


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise NetworkError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _transfer_value(value: bytes | Mapping[str, Any]) -> tuple[Mapping[str, Any], bytes]:
    if isinstance(value, bytes):
        if len(value) > MAX_TRANSFER_BYTES:
            raise NetworkError("silo transfer exceeds the 16-mebibyte transaction bound")
        try:
            decoded = json.loads(
                value, object_pairs_hook=_unique_json_pairs,
                parse_constant=lambda item: (_ for _ in ()).throw(NetworkError(f"non-finite JSON number: {item}")),
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise NetworkError("silo transfer is not bounded canonical JSON") from exc
        if not isinstance(decoded, Mapping) or canonical_bytes(decoded) != value:
            raise NetworkError("silo transfer is not bounded canonical JSON")
        return decoded, value
    if not isinstance(value, Mapping):
        raise NetworkError("silo transfer must be canonical JSON bytes or an object")
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_TRANSFER_BYTES:
        raise NetworkError("silo transfer exceeds the 16-mebibyte transaction bound")
    return value, encoded


def _transfer_object_bytes(value: Any) -> tuple[str, bytes]:
    item = _strict(value, {"digest", "bytes_base64url"}, "silo transfer object")
    digest = _digest(item["digest"], "transfer object digest")
    encoded = item["bytes_base64url"]
    if not isinstance(encoded, str) or len(encoded) > ((MAX_OBJECT_BYTES + 2) // 3) * 4 or "=" in encoded or not re.fullmatch(r"[A-Za-z0-9_-]*", encoded):
        raise NetworkError("transfer object bytes are not bounded canonical unpadded base64url")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise NetworkError("transfer object bytes are not bounded canonical unpadded base64url") from exc
    if len(raw) > MAX_OBJECT_BYTES or _base64url_encode(raw) != encoded or digest_bytes(raw) != digest:
        raise NetworkError("transfer object bytes do not match their bounded canonical identity")
    return digest, raw


def _verify_transfer_continuity(
    publisher: PublisherRecord, continuity: tuple[KeyContinuityRecord, ...],
) -> None:
    if len(continuity) != len(publisher.key_continuity_digests):
        raise NetworkError("transfer key continuity inventory is incomplete")
    previous_key = digest_bytes(_canonical_b64(publisher.genesis_public_key_base64url, 32, "genesis_public_key_base64url"))
    previous_record: str | None = None
    for index, record in enumerate(continuity):
        expected_digest = publisher.key_continuity_digests[index]
        if record.canonical_digest() != expected_digest or record.sequence != index + 1 or record.previous_record_digest != previous_record:
            raise NetworkError("transfer key continuity chain is not exact")
        previous_key = verify_key_continuity(record, previous_key)
        previous_record = expected_digest
    if publisher.active_key_ids != (previous_key,):
        raise NetworkError("transfer publisher active key does not match continuity")


def build_silo_transfer(
    commit: SiloCommit, head: SignedHead, publisher: PublisherRecord,
    store: ContentAddressedStore,
) -> dict[str, Any]:
    """Build one bounded transport envelope for the selected native snapshot."""

    receipt = build_silo_assessment_receipt(commit, store)
    verify_head(head, publisher)
    if head.commit_digest != commit.canonical_digest():
        raise NetworkError("signed head does not select the transferred commit")
    continuity = tuple(
        KeyContinuityRecord.from_dict(store.read_record("keys", digest))
        for digest in publisher.key_continuity_digests
    )
    _verify_transfer_continuity(publisher, continuity)
    objects: dict[str, bytes] = {}
    for entry in commit.census:
        objects[entry.object_record.object_digest] = store.read_object(entry.object_record)
    manifest = {
        "schema_version": EXPORT_SCHEMA,
        "publisher_digest": digest_bytes(canonical_bytes(publisher.to_dict())),
        "commit_digest": commit.canonical_digest(),
        "head_digest": head.canonical_digest(),
        "assessment_receipt_digest": digest_bytes(canonical_bytes(receipt.to_dict())),
    }
    result = {
        "schema_version": TRANSFER_SCHEMA,
        "portable_manifest": manifest,
        "publisher": publisher.to_dict(),
        "key_continuity": [record.to_dict() for record in continuity],
        "signed_head": head.to_dict(),
        "commit": commit.to_dict(),
        "assessment_receipt": receipt.to_dict(),
        "objects": [
            {"digest": digest, "bytes_base64url": _base64url_encode(objects[digest])}
            for digest in sorted(objects)
        ],
    }
    if len(canonical_bytes(result)) > MAX_TRANSFER_BYTES:
        raise NetworkError("silo transfer exceeds the 16-mebibyte transaction bound")
    return result


def materialize_silo_transfer(
    value: bytes | Mapping[str, Any], destination: str | Path,
) -> dict[str, Any]:
    """Validate a transfer, materialize its native tree, then revalidate it."""

    transfer, _encoded = _transfer_value(value)
    transfer = _strict(transfer, {"schema_version", "portable_manifest", "publisher", "key_continuity", "signed_head", "commit", "assessment_receipt", "objects"}, "silo transfer")
    if transfer["schema_version"] != TRANSFER_SCHEMA:
        raise NetworkError("unsupported silo transfer schema_version")
    manifest = _strict(transfer["portable_manifest"], {"schema_version", "publisher_digest", "commit_digest", "head_digest", "assessment_receipt_digest"}, "portable manifest")
    if manifest["schema_version"] != EXPORT_SCHEMA:
        raise NetworkError("unsupported portable manifest schema_version")
    for field in ("publisher_digest", "commit_digest", "head_digest", "assessment_receipt_digest"):
        _digest(manifest[field], field)
    publisher = PublisherRecord.from_dict(transfer["publisher"])
    commit = SiloCommit.from_dict(transfer["commit"])
    head = SignedHead.from_dict(transfer["signed_head"])
    receipt = _strict(transfer["assessment_receipt"], {"schema_version", "commit_digest", "mechanism_digest", "assessment"}, "assessment receipt")
    continuity_values = _array(transfer["key_continuity"], "key_continuity")
    continuity = tuple(KeyContinuityRecord.from_dict(item) for item in continuity_values)
    object_values = _array(transfer["objects"], "transfer objects")
    objects: dict[str, bytes] = {}
    for item in object_values:
        digest, raw = _transfer_object_bytes(item)
        if digest in objects:
            raise NetworkError("silo transfer contains a duplicate object digest")
        objects[digest] = raw
    expected_objects = {entry.object_record.object_digest for entry in commit.census}
    if set(objects) != expected_objects:
        raise NetworkError("silo transfer object inventory is not the exact selected commit closure")
    if (
        digest_bytes(canonical_bytes(publisher.to_dict())) != manifest["publisher_digest"]
        or commit.canonical_digest() != manifest["commit_digest"]
        or head.canonical_digest() != manifest["head_digest"]
        or digest_bytes(canonical_bytes(receipt)) != manifest["assessment_receipt_digest"]
    ):
        raise NetworkError("portable manifest does not bind the transferred records")
    verify_head(head, publisher)
    if head.commit_digest != commit.canonical_digest() or head.publisher_id != publisher.publisher_id or commit.publisher_id != publisher.publisher_id:
        raise NetworkError("transferred publisher, commit, and signed head are inconsistent")
    _verify_transfer_continuity(publisher, continuity)
    destination = Path(destination)
    if destination.exists():
        raise NetworkError("transfer destination must be absent")
    with tempfile.TemporaryDirectory(prefix="vstd-transfer-") as temporary:
        source_store = ContentAddressedStore(Path(temporary) / "source")
        for entry in commit.census:
            observed = source_store.add_object(
                objects[entry.object_record.object_digest], entry.object_record.media_type,
                entry.object_record.artifact_kind, entry.object_record.declared_schema_id,
            )
            if observed != entry.object_record:
                raise NetworkError("transfer object declaration does not bind its bytes")
        for expected_digest, record in zip(publisher.key_continuity_digests, continuity):
            if source_store.put_record("keys", record.to_dict()) != expected_digest:
                raise NetworkError("transfer key continuity record does not bind its digest")
        computed_receipt = build_silo_assessment_receipt(commit, source_store).to_dict()
        if computed_receipt != receipt or canonical_bytes(computed_receipt) != canonical_bytes(receipt):
            raise NetworkError("transferred assessment receipt does not match local recomputation")
        export_root = Path(temporary) / "export"
        observed_manifest = export_silo(commit, head, publisher, source_store, export_root)
        if observed_manifest != manifest:
            raise NetworkError("transferred portable manifest does not match native export")
        return rebuild_silo(export_root, destination)


class _BoundedHttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        self.redirects = 0

    def redirect_request(self, request: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> urllib.request.Request:
        self.redirects += 1
        if self.redirects > MAX_TRANSFER_REDIRECTS or urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise NetworkError("silo transfer redirect is not bounded HTTPS")
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is None:
            raise NetworkError("silo transfer redirect was refused")
        for header in ("Authorization", "Cookie", "Proxy-Authorization"):
            redirected.remove_header(header)
        return redirected


def download_silo_transfer(
    url: str, destination: str | Path, *, opener: Any | None = None,
) -> dict[str, Any]:
    """Download one bounded HTTPS transfer; transport success is not trust."""

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise NetworkError("silo transfer URL must be credential-free HTTPS without a fragment")
    client = opener or urllib.request.build_opener(_BoundedHttpsRedirectHandler())
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.vstd.silo-transfer+json, application/json", "Accept-Encoding": "identity"})
    try:
        response = client.open(request, timeout=TRANSFER_TIMEOUT_SECONDS)
        with response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise NetworkError("silo transfer download did not return HTTP 200")
            final_url = response.geturl()
            if urllib.parse.urlsplit(final_url).scheme.lower() != "https":
                raise NetworkError("silo transfer final URL is not HTTPS")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in {"application/json", "application/vnd.vstd.silo-transfer+json"}:
                raise NetworkError("silo transfer response has an unsupported content type")
            content_encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
            if content_encoding not in {"", "identity"}:
                raise NetworkError("silo transfer response must use identity content encoding")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_TRANSFER_BYTES):
                raise NetworkError("silo transfer response exceeds its declared byte bound")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(65536, MAX_TRANSFER_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TRANSFER_BYTES:
                    raise NetworkError("silo transfer response exceeds its byte bound")
                chunks.append(chunk)
            if length is not None and total != int(length):
                raise NetworkError("silo transfer response was truncated")
    except NetworkError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise NetworkError("silo transfer download failed") from exc
    return materialize_silo_transfer(b"".join(chunks), destination)


def clone_silo(source: str | Path, destination: str | Path, *, opener: Any | None = None) -> dict[str, Any]:
    """Clone from a native directory, local transfer file, or bounded HTTPS endpoint."""

    text = str(source)
    windows_path = len(text) >= 3 and text[0].isalpha() and text[1] == ":" and text[2] in {"\\", "/"}
    if not isinstance(source, Path) and not windows_path:
        parsed = urllib.parse.urlsplit(text)
        if parsed.scheme:
            if parsed.scheme.lower() != "https":
                raise NetworkError("network clone sources must use HTTPS")
            return download_silo_transfer(text, destination, opener=opener)
    local = Path(source)
    try:
        source_stat = local.lstat()
    except OSError:
        return rebuild_silo(local, destination)
    if stat.S_ISDIR(source_stat.st_mode):
        return rebuild_silo(local, destination)
    return materialize_silo_transfer(
        _read_bounded_regular(local, MAX_TRANSFER_BYTES, "silo transfer"), destination
    )


def export_silo(commit: SiloCommit, head: SignedHead, publisher: PublisherRecord,
                store: ContentAddressedStore, destination: str | Path) -> dict[str, Any]:
    assessment = assess_silo(commit, store)
    assessment_receipt = build_silo_assessment_receipt(commit, store)
    if assessment.reconstructibility != "COMPLETE":
        raise NetworkError("cannot export an incomplete byte closure")
    verify_head(head, publisher)
    if head.commit_digest != commit.canonical_digest():
        raise NetworkError("signed head does not select the exported commit")
    continuity_values = tuple(
        store.read_record("keys", digest) for digest in publisher.key_continuity_digests
    )
    manifest_preview = {
        "schema_version": EXPORT_SCHEMA,
        "publisher_digest": digest_bytes(canonical_bytes(publisher.to_dict())),
        "commit_digest": commit.canonical_digest(),
        "head_digest": head.canonical_digest(),
        "assessment_receipt_digest": digest_bytes(canonical_bytes(assessment_receipt.to_dict())),
    }
    export_size = sum(entry.object_record.size_bytes for entry in commit.census) + sum(
        len(canonical_bytes(value)) for value in (
            commit.to_dict(), head.to_dict(), publisher.to_dict(),
            assessment_receipt.to_dict(), manifest_preview, *continuity_values,
        )
    )
    if export_size > MAX_EXPORT_BYTES:
        raise NetworkError("silo export exceeds the 16-mebibyte transaction bound")
    destination = Path(destination)
    if destination.exists():
        raise NetworkError("export destination must be absent")
    destination.mkdir(parents=True)
    try:
        target = ContentAddressedStore(destination)
        target.initialize()
        for entry in commit.census:
            target.add_object(store.read_object(entry.object_record), entry.object_record.media_type, entry.object_record.artifact_kind, entry.object_record.declared_schema_id)
        commit_digest = target.put_record("commits", commit.to_dict())
        head_digest = target.put_record("heads", head.to_dict())
        publisher_digest = target.put_record("publishers", publisher.to_dict())
        assessment_receipt_digest = target.put_record("assessments", assessment_receipt.to_dict())
        for continuity_digest, continuity_value in zip(publisher.key_continuity_digests, continuity_values):
            if target.put_record("keys", continuity_value) != continuity_digest:
                raise NetworkError("key continuity digest does not bind its retained record")
        manifest = {"schema_version": EXPORT_SCHEMA, "publisher_digest": publisher_digest, "commit_digest": commit_digest, "head_digest": head_digest, "assessment_receipt_digest": assessment_receipt_digest}
        (destination / "export.json").write_bytes(canonical_bytes(manifest))
        return manifest
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _export_inventory(root: Path) -> tuple[set[str], set[str]]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise NetworkError("export root is unavailable") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or getattr(root_info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise NetworkError("export root must be an ordinary non-link directory")
    files: set[str] = set()
    directories: set[str] = set()
    total_bytes = 0
    entries_seen = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = os.scandir(directory)
        except OSError as exc:
            raise NetworkError("export tree is unavailable") from exc
        with children:
            for child in children:
                entries_seen += 1
                if entries_seen > MAX_EXPORT_ENTRIES:
                    raise NetworkError("export tree exceeds its entry bound")
                try:
                    info = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise NetworkError("export tree entry is unavailable") from exc
                if child.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                    raise NetworkError("exports must not contain symbolic links or reparse points")
                relative = Path(child.path).relative_to(root).as_posix()
                if stat.S_ISDIR(info.st_mode):
                    directories.add(relative)
                    pending.append(Path(child.path))
                elif stat.S_ISREG(info.st_mode):
                    total_bytes += info.st_size
                    if info.st_size > MAX_RECORD_BYTES or total_bytes > MAX_EXPORT_BYTES:
                        raise NetworkError("export tree exceeds its byte bound")
                    files.add(relative)
                else:
                    raise NetworkError("export tree contains a non-regular entry")
    return files, directories


def rebuild_silo(export_root: str | Path, destination: str | Path) -> dict[str, Any]:
    source = Path(export_root)
    observed_files, observed_direct = _export_inventory(source)
    try:
        manifest = json.loads(_read_bounded_regular(source / "export.json", MAX_RECORD_BYTES, "export manifest"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkError("export manifest is unavailable or malformed") from exc
    _strict(manifest, {"schema_version", "publisher_digest", "commit_digest", "head_digest", "assessment_receipt_digest"}, "export manifest")
    if manifest["schema_version"] != EXPORT_SCHEMA:
        raise NetworkError("unsupported export schema_version")
    source_store = ContentAddressedStore(source)
    publisher = PublisherRecord.from_dict(source_store.read_record("publishers", manifest["publisher_digest"]))
    commit = SiloCommit.from_dict(source_store.read_record("commits", manifest["commit_digest"]))
    head = SignedHead.from_dict(source_store.read_record("heads", manifest["head_digest"]))
    assessment_receipt = source_store.read_record("assessments", manifest["assessment_receipt_digest"])
    verify_head(head, publisher)
    current_assessment = assess_silo(commit, source_store)
    if (
        head.commit_digest != commit.canonical_digest()
        or current_assessment.reconstructibility != "COMPLETE"
        or assessment_receipt != build_silo_assessment_receipt(commit, source_store).to_dict()
    ):
        raise NetworkError("export does not reconstruct its signed complete byte closure")
    genesis_raw = _canonical_b64(publisher.genesis_public_key_base64url, 32, "genesis_public_key_base64url")
    expected_key = digest_bytes(genesis_raw)
    continuity_records = [
        KeyContinuityRecord.from_dict(source_store.read_record("keys", digest))
        for digest in publisher.key_continuity_digests
    ]
    continuity_records.sort(key=lambda record: record.sequence)
    previous_digest: str | None = None
    for expected_sequence, record in enumerate(continuity_records, start=1):
        if record.sequence != expected_sequence or record.previous_record_digest != previous_digest:
            raise NetworkError("key continuity record chain is not digest-linked")
        expected_key = verify_key_continuity(record, expected_key)
        previous_digest = record.canonical_digest()
    if publisher.active_key_ids != (expected_key,):
        raise NetworkError("publisher active key does not match the verified continuity chain")
    def record_path(kind: str, digest: str) -> str:
        return f"records/{kind}/{_digest(digest).split(':', 1)[1]}.json"

    allowed_files = {
        "export.json",
        record_path("commits", manifest["commit_digest"]),
        record_path("heads", manifest["head_digest"]),
        record_path("publishers", manifest["publisher_digest"]),
        record_path("assessments", manifest["assessment_receipt_digest"]),
        *(record_path("keys", digest) for digest in publisher.key_continuity_digests),
        *(f"objects/sha256/{entry.object_record.object_digest.split(':', 1)[1]}" for entry in commit.census),
    }
    allowed_directories = set(STORE_DIRS)
    if observed_files != allowed_files or observed_direct != allowed_directories:
        raise NetworkError("export tree does not exactly match its signed content inventory")

    retained: dict[str, bytes] = {}
    for relative in sorted(allowed_files):
        maximum = MAX_OBJECT_BYTES if relative.startswith("objects/") else MAX_RECORD_BYTES
        data = _read_bounded_regular(source / relative, maximum, "export inventory member")
        if relative == "export.json":
            if data != canonical_bytes(manifest):
                raise NetworkError("export manifest is not canonical")
        elif relative.startswith("objects/"):
            if digest_bytes(data).split(":", 1)[1] != Path(relative).name:
                raise NetworkError("export object filename does not bind its bytes")
        else:
            if digest_bytes(data).split(":", 1)[1] != Path(relative).stem:
                raise NetworkError("export record filename does not bind its bytes")
        retained[relative] = data

    destination = Path(destination)
    if destination.exists():
        raise NetworkError("rebuild destination must be absent")
    destination.mkdir(parents=True)
    try:
        for relative in sorted(allowed_directories, key=lambda item: (item.count("/"), item)):
            (destination / relative).mkdir(exist_ok=True)
        for relative, data in retained.items():
            with (destination / relative).open("xb") as stream:
                stream.write(data)

        rebuilt_files, rebuilt_directories = _export_inventory(destination)
        if rebuilt_files != allowed_files or rebuilt_directories != allowed_directories:
            raise NetworkError("rebuilt destination does not exactly match the validated export inventory")
        for relative, expected_bytes in retained.items():
            maximum = MAX_OBJECT_BYTES if relative.startswith("objects/") else MAX_RECORD_BYTES
            rebuilt_bytes = _read_bounded_regular(
                destination / relative, maximum, "rebuilt destination member"
            )
            if rebuilt_bytes != expected_bytes:
                raise NetworkError("rebuilt destination bytes differ from the validated export")

        rebuilt_store = ContentAddressedStore(destination)
        rebuilt_manifest = json.loads(
            _read_bounded_regular(destination / "export.json", MAX_RECORD_BYTES, "rebuilt export manifest")
        )
        if rebuilt_manifest != manifest or canonical_bytes(rebuilt_manifest) != retained["export.json"]:
            raise NetworkError("rebuilt export manifest does not preserve canonical identity")
        rebuilt_publisher = PublisherRecord.from_dict(
            rebuilt_store.read_record("publishers", manifest["publisher_digest"])
        )
        rebuilt_commit = SiloCommit.from_dict(
            rebuilt_store.read_record("commits", manifest["commit_digest"])
        )
        rebuilt_head = SignedHead.from_dict(
            rebuilt_store.read_record("heads", manifest["head_digest"])
        )
        rebuilt_receipt = rebuilt_store.read_record(
            "assessments", manifest["assessment_receipt_digest"]
        )
        verify_head(rebuilt_head, rebuilt_publisher)
        rebuilt_assessment = assess_silo(rebuilt_commit, rebuilt_store)
        if (
            rebuilt_commit.canonical_digest() != manifest["commit_digest"]
            or rebuilt_head.canonical_digest() != manifest["head_digest"]
            or rebuilt_head.commit_digest != rebuilt_commit.canonical_digest()
            or rebuilt_assessment.reconstructibility != "COMPLETE"
            or rebuilt_receipt != build_silo_assessment_receipt(rebuilt_commit, rebuilt_store).to_dict()
        ):
            raise NetworkError("rebuilt destination does not reconstruct its signed complete byte closure")

        rebuilt_genesis = _canonical_b64(
            rebuilt_publisher.genesis_public_key_base64url, 32, "genesis_public_key_base64url"
        )
        rebuilt_expected_key = digest_bytes(rebuilt_genesis)
        rebuilt_continuity = [
            KeyContinuityRecord.from_dict(rebuilt_store.read_record("keys", digest))
            for digest in rebuilt_publisher.key_continuity_digests
        ]
        rebuilt_continuity.sort(key=lambda record: record.sequence)
        rebuilt_previous_digest: str | None = None
        for expected_sequence, record in enumerate(rebuilt_continuity, start=1):
            if record.sequence != expected_sequence or record.previous_record_digest != rebuilt_previous_digest:
                raise NetworkError("rebuilt key continuity record chain is not digest-linked")
            rebuilt_expected_key = verify_key_continuity(record, rebuilt_expected_key)
            rebuilt_previous_digest = record.canonical_digest()
        if rebuilt_publisher.active_key_ids != (rebuilt_expected_key,):
            raise NetworkError("rebuilt publisher active key does not match the verified continuity chain")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return dict(manifest)


def diff_commits(left: SiloCommit, right: SiloCommit) -> dict[str, Any]:
    first = {entry.path: entry.object_record.object_digest for entry in left.census}
    second = {entry.path: entry.object_record.object_digest for entry in right.census}
    return {"added": sorted(second.keys() - first.keys()), "removed": sorted(first.keys() - second.keys()), "changed": sorted(path for path in first.keys() & second.keys() if first[path] != second[path]), "claim_boundary": "Digest and path differences do not establish a semantic contradiction."}


__all__ = [
    "ASSESSMENT_SCHEMA", "AUTHORITY_ACTOR_SCOPES", "AUTHORITY_ACTOR_SCOPE_VERSION", "AUTHORITY_AXIOM_AGENCY", "AUTHORITY_AXIOM_AGENCY_VERSION", "AUTHORITY_MODEL_SCHEMA", "ArtifactRelation", "AuthorityModel", "AuthorityState", "AuthorityTransition",
    "ASSESSMENT_RECEIPT_SCHEMA", "COMMIT_SCHEMA", "COMPOSITION_ASSESSMENT_RECEIPT_SCHEMA", "COMPOSITION_ASSESSMENT_SCHEMA", "COMPOSITION_SCHEMA", "ContentAddressedStore",
    "CensusEntry", "DerivationEdge", "DirectoryEntry", "EXPORT_SCHEMA", "HEAD_SCHEMA",
    "KeyContinuityRecord", "LocalAuthorityAddition", "MAX_PRIVATE_KEY_BYTES", "MAX_RECORD_BYTES", "NetworkError",
    "OBJECT_SCHEMA", "ObjectRecord", "PUBLISHER_SCHEMA", "PUSH_REQUEST_SCHEMA", "TRANSFER_SCHEMA",
    "PublisherRecord", "SelfDerivationRecord", "SignedDirectorySnapshot", "SignedHead", "SiloAssessment", "SiloAssessmentReceipt", "SiloCommit", "SiloComposition", "SiloCompositionAssessment", "SiloCompositionAssessmentReceipt", "assess_composition",
    "assess_silo", "authority_actor_scope_digest", "authority_axiom_agency_digest", "build_silo_assessment_receipt", "build_silo_composition_assessment_receipt", "build_silo_transfer", "canonical_bytes", "census_boundary_members", "clone_silo", "diff_commits", "digest_bytes", "download_silo_transfer", "export_silo", "materialize_silo_transfer",
    "create_key_continuity", "publisher_from_private_key", "rebuild_silo", "sign_directory_snapshot",
    "recheck_silo_composition_assessment_receipt", "self_derivation_mechanism_bytes", "silo_composition_mechanism_bytes", "sign_head", "verify_directory_snapshot", "verify_head", "verify_key_continuity",
]
