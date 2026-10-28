"""Terminology: Concise Binary Object Representation (CBOR);
Internet Engineering Task Force (IETF); JavaScript Object Notation (JSON);
Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).

Experimental implementation of ``draft-le-scitt-derived-subjects-00``.

The draft is an individual Internet-Draft, not an adopted IETF standard.  The
labels and algorithms in this module are therefore pinned to revision ``-00``
and MUST NOT be silently reused for a later revision.

Derived Subjects groups statements about the same semantic subject.  It does
not bind a complete VSTD claim coordinate.  :class:`VstdDerivedSubjectBinding`
keeps that second binding explicit so a change to predicate, parameters, or
verification bounds cannot inherit epistemic strength from an unchanged
``sub`` value.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .adapter import VstdCoordinates, canonical_json_bytes


DRAFT_REVISION = "draft-le-scitt-derived-subjects-00"
SUBJECT_PREFIX = "scitt-derived-subject-v1."
DST = b"scitt-derived-subject/v1"
VSTD_MAPPING_VERSION = "verifier-vstd-derived-subject/0.1"
VSTD_MAPPING_CONTEXT = b"verifier:vstd-derived-subject/0.1"
DEFAULT_MAX_INPUT_BYTES = 1_048_576
DEFAULT_MAX_IDENTIFIERS = 4_096
_MAX_UINT64 = (1 << 64) - 1


class DerivedSubjectError(ValueError):
    """Raised when a Derived Subjects value is malformed or non-canonical."""


class DerivedSubjectResourceLimit(DerivedSubjectError):
    """Raised when local, explicitly declared decoding limits are exhausted."""


class DerivedSubjectComparison(str, Enum):
    """Three-valued comparison from the pinned draft."""

    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"


def be64(value: int) -> bytes:
    """Encode a non-negative integer as eight unsigned big-endian bytes."""

    if type(value) is not int or not 0 <= value <= _MAX_UINT64:
        raise DerivedSubjectError("BE64 input must be an unsigned 64-bit integer")
    return value.to_bytes(8, "big")


def lp64(value: bytes) -> bytes:
    """Encode bytes using the draft's eight-byte length prefix."""

    if not isinstance(value, bytes):
        raise DerivedSubjectError("lp64 input must be bytes")
    return be64(len(value)) + value


@dataclass(frozen=True, order=True)
class ScopedIdentifier:
    """One ``(scope, identifier)`` pair."""

    scope: bytes
    identifier: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.scope, bytes) or not isinstance(self.identifier, bytes):
            raise DerivedSubjectError("scope and identifier must be bytes")

    def encoded(self) -> bytes:
        return lp64(self.scope) + lp64(self.identifier)


@dataclass(frozen=True)
class DerivedSubjectValue:
    """Semantic Value whose identifier collection has mathematical-set semantics."""

    context: bytes
    content: bytes
    identifiers: tuple[ScopedIdentifier, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.context, bytes) or not isinstance(self.content, bytes):
            raise DerivedSubjectError("context and content must be bytes")
        if not isinstance(self.identifiers, tuple) or not all(
            isinstance(item, ScopedIdentifier) for item in self.identifiers
        ):
            raise DerivedSubjectError("identifiers must be a tuple of ScopedIdentifier")
        encoded = [item.encoded() for item in self.identifiers]
        if len(set(encoded)) != len(encoded):
            raise DerivedSubjectError("identifiers must be unique")
        object.__setattr__(
            self,
            "identifiers",
            tuple(item for _, item in sorted(zip(encoded, self.identifiers))),
        )


def scoped_identifier_from_bytes(value: bytes) -> ScopedIdentifier:
    """Decode one complete ``ScopedIdentifierBytes`` value."""

    if not isinstance(value, bytes):
        raise DerivedSubjectError("encoded scoped identifier must be bytes")
    if len(value) < 16:
        raise DerivedSubjectError("encoded scoped identifier is truncated")
    scope_length = int.from_bytes(value[:8], "big")
    scope_end = 8 + scope_length
    if scope_end + 8 > len(value):
        raise DerivedSubjectError("encoded scoped identifier scope is truncated")
    identifier_length = int.from_bytes(value[scope_end : scope_end + 8], "big")
    identifier_start = scope_end + 8
    identifier_end = identifier_start + identifier_length
    if identifier_end != len(value):
        raise DerivedSubjectError(
            "encoded scoped identifier is truncated or has trailing bytes"
        )
    return ScopedIdentifier(value[8:scope_end], value[identifier_start:identifier_end])


def binding_bytes(value: DerivedSubjectValue) -> bytes:
    """Serialize ``Value`` to the draft's collision-resistant BindingBytes."""

    if not isinstance(value, DerivedSubjectValue):
        raise DerivedSubjectError("value must be DerivedSubjectValue")
    encoded = tuple(item.encoded() for item in value.identifiers)
    return lp64(value.context) + lp64(value.content) + be64(len(encoded)) + b"".join(
        encoded
    )


def subject_preimage(value: DerivedSubjectValue) -> bytes:
    return lp64(DST) + binding_bytes(value)


def subject_digest(value: DerivedSubjectValue) -> bytes:
    return hashlib.sha256(subject_preimage(value)).digest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str, label: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise DerivedSubjectError(f"{label} must be unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise DerivedSubjectError(f"{label} must be canonical base64url") from exc
    if _b64url_encode(decoded) != value:
        raise DerivedSubjectError(f"{label} must be canonical unpadded base64url")
    return decoded


def subject_text(value: DerivedSubjectValue) -> str:
    return SUBJECT_PREFIX + _b64url_encode(subject_digest(value))


def parse_subject_text(value: str) -> bytes:
    """Parse a subject in this profile; non-profile subjects are an error here."""

    if not isinstance(value, str) or not value.startswith(SUBJECT_PREFIX):
        raise DerivedSubjectError("subject does not use the pinned Derived Subjects prefix")
    digest = _b64url_decode(value[len(SUBJECT_PREFIX) :], "subject digest")
    if len(digest) != hashlib.sha256().digest_size:
        raise DerivedSubjectError("subject digest must contain exactly 32 bytes")
    return digest


def compare_subject(
    observed_subject: str,
    candidate: DerivedSubjectValue,
    *,
    semantics_established: bool,
    draft_revision: str = DRAFT_REVISION,
) -> DerivedSubjectComparison:
    """Compare only when the relying profile establishes the Value semantics.

    A malformed value that claims the profile prefix is an error.  A subject
    outside the profile or a profile-revision/semantic mismatch is
    ``NOT_ESTABLISHED``, never an inferred match.
    """

    if not isinstance(observed_subject, str):
        raise DerivedSubjectError("observed subject must be a string")
    if not observed_subject.startswith(SUBJECT_PREFIX):
        return DerivedSubjectComparison.NOT_ESTABLISHED
    parse_subject_text(observed_subject)
    if not semantics_established or draft_revision != DRAFT_REVISION:
        return DerivedSubjectComparison.NOT_ESTABLISHED
    if observed_subject == subject_text(candidate):
        return DerivedSubjectComparison.MATCH
    return DerivedSubjectComparison.NO_MATCH


def _reject_constant(value: str) -> None:
    raise DerivedSubjectError(f"JSON constant {value!r} is not permitted")


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DerivedSubjectError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def parse_value_json(
    data: bytes,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_identifiers: int = DEFAULT_MAX_IDENTIFIERS,
) -> DerivedSubjectValue:
    """Decode the draft's JSON representation with canonicality checks."""

    if not isinstance(data, bytes):
        raise DerivedSubjectError("JSON input must be bytes")
    if type(max_input_bytes) is not int or max_input_bytes < 0:
        raise DerivedSubjectError("max_input_bytes must be a non-negative integer")
    if type(max_identifiers) is not int or max_identifiers < 0:
        raise DerivedSubjectError("max_identifiers must be a non-negative integer")
    if len(data) > max_input_bytes:
        raise DerivedSubjectResourceLimit("JSON input exceeds max_input_bytes")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DerivedSubjectError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DerivedSubjectError("Derived Subjects JSON is malformed") from exc
    if not isinstance(value, dict):
        raise DerivedSubjectError("Derived Subjects JSON must be an object")
    expected = {"context", "content", "identifiers"}
    if set(value) != expected:
        raise DerivedSubjectError(
            "Derived Subjects JSON keys mismatch; "
            f"missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)}"
        )
    identifiers = value["identifiers"]
    if not isinstance(identifiers, list) or not all(
        isinstance(item, str) for item in identifiers
    ):
        raise DerivedSubjectError("identifiers must be an array of base64url strings")
    if len(identifiers) > max_identifiers:
        raise DerivedSubjectResourceLimit("identifier count exceeds max_identifiers")
    encoded = [
        _b64url_decode(item, f"identifiers[{index}]")
        for index, item in enumerate(identifiers)
    ]
    if encoded != sorted(encoded):
        raise DerivedSubjectError("identifiers must be in canonical octet order")
    if len(set(encoded)) != len(encoded):
        raise DerivedSubjectError("identifiers must not contain duplicates")
    return DerivedSubjectValue(
        context=_b64url_decode(value["context"], "context"),
        content=_b64url_decode(value["content"], "content"),
        identifiers=tuple(scoped_identifier_from_bytes(item) for item in encoded),
    )


def value_to_json_bytes(value: DerivedSubjectValue) -> bytes:
    """Encode the JSON form deterministically; JSON member order is not semantic."""

    return canonical_json_bytes(
        {
            "context": _b64url_encode(value.context),
            "content": _b64url_encode(value.content),
            "identifiers": [
                _b64url_encode(item.encoded()) for item in value.identifiers
            ],
        }
    )


def _cbor2():
    try:
        import cbor2
    except ImportError as exc:
        raise DerivedSubjectError(
            "CBOR interchange requires the pinned 'scitt' optional dependency"
        ) from exc
    return cbor2


def parse_value_cbor(
    data: bytes,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_identifiers: int = DEFAULT_MAX_IDENTIFIERS,
) -> DerivedSubjectValue:
    """Decode the optional deterministic CBOR interchange representation."""

    if not isinstance(data, bytes):
        raise DerivedSubjectError("CBOR input must be bytes")
    if type(max_input_bytes) is not int or max_input_bytes < 0:
        raise DerivedSubjectError("max_input_bytes must be a non-negative integer")
    if type(max_identifiers) is not int or max_identifiers < 0:
        raise DerivedSubjectError("max_identifiers must be a non-negative integer")
    if len(data) > max_input_bytes:
        raise DerivedSubjectResourceLimit("CBOR input exceeds max_input_bytes")
    cbor2 = _cbor2()
    try:
        decoded = cbor2.loads(data)
    except Exception as exc:
        raise DerivedSubjectError("Derived Subjects CBOR is malformed") from exc
    try:
        deterministic = cbor2.dumps(decoded, canonical=True)
    except Exception as exc:
        raise DerivedSubjectError("Derived Subjects CBOR is outside the profile") from exc
    if deterministic != data:
        raise DerivedSubjectError(
            "CBOR must use core deterministic encoding without duplicate map keys"
        )
    if not isinstance(decoded, dict):
        raise DerivedSubjectError("Derived Subjects CBOR must be a map")
    expected = {"context", "content", "identifiers"}
    if set(decoded) != expected:
        raise DerivedSubjectError("Derived Subjects CBOR keys mismatch")
    if not isinstance(decoded["context"], bytes) or not isinstance(
        decoded["content"], bytes
    ):
        raise DerivedSubjectError("CBOR context and content must be byte strings")
    identifiers = decoded["identifiers"]
    if not isinstance(identifiers, list) or not all(
        isinstance(item, bytes) for item in identifiers
    ):
        raise DerivedSubjectError("CBOR identifiers must be an array of byte strings")
    if len(identifiers) > max_identifiers:
        raise DerivedSubjectResourceLimit("identifier count exceeds max_identifiers")
    if identifiers != sorted(identifiers):
        raise DerivedSubjectError("identifiers must be in canonical octet order")
    if len(set(identifiers)) != len(identifiers):
        raise DerivedSubjectError("identifiers must not contain duplicates")
    return DerivedSubjectValue(
        context=decoded["context"],
        content=decoded["content"],
        identifiers=tuple(scoped_identifier_from_bytes(item) for item in identifiers),
    )


def value_to_cbor_bytes(value: DerivedSubjectValue) -> bytes:
    """Encode the optional CBOR form using RFC 8949 core deterministic order."""

    cbor2 = _cbor2()
    return cbor2.dumps(
        {
            "context": value.context,
            "content": value.content,
            "identifiers": [item.encoded() for item in value.identifiers],
        },
        canonical=True,
    )


@dataclass(frozen=True)
class VstdDerivedSubjectBinding:
    """Derived subject plus the VSTD distinctions that ``sub`` cannot carry."""

    draft_revision: str
    mapping_version: str
    subject: str
    claim_coordinate_sha256: str
    evidence_bounds_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "draft_revision": self.draft_revision,
            "mapping_version": self.mapping_version,
            "subject": self.subject,
            "claim_coordinate_sha256": self.claim_coordinate_sha256,
            "evidence_bounds_sha256": self.evidence_bounds_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VstdDerivedSubjectBinding":
        expected = {
            "draft_revision",
            "mapping_version",
            "subject",
            "claim_coordinate_sha256",
            "evidence_bounds_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise DerivedSubjectError("VSTD Derived Subject binding keys mismatch")
        for field in expected:
            if not isinstance(value[field], str) or not value[field]:
                raise DerivedSubjectError(f"{field} must be a non-empty string")
        parse_subject_text(value["subject"])
        for field in ("claim_coordinate_sha256", "evidence_bounds_sha256"):
            digest = value[field]
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise DerivedSubjectError(f"{field} must be a lowercase SHA-256 digest")
        return cls(**{field: value[field] for field in expected})


def vstd_value(coordinates: VstdCoordinates) -> DerivedSubjectValue:
    """Map VSTD subject/artifacts to Value without collapsing artifact roles."""

    if not isinstance(coordinates, VstdCoordinates):
        raise DerivedSubjectError("coordinates must be VstdCoordinates")
    identifiers = tuple(
        ScopedIdentifier(
            scope=b"vstd-artifact-role/" + role.encode("utf-8"),
            identifier=bytes.fromhex(digest),
        )
        for role, digest in coordinates.artifact_digests.items()
    )
    return DerivedSubjectValue(
        context=VSTD_MAPPING_CONTEXT,
        content=coordinates.subject.encode("utf-8"),
        identifiers=identifiers,
    )


def derive_vstd_subject_binding(
    coordinates: VstdCoordinates,
) -> VstdDerivedSubjectBinding:
    """Derive subject grouping and separately bind VSTD claim/bounds semantics."""

    coordinate = canonical_json_bytes(
        {
            "claim_id": coordinates.claim_id,
            "subject": coordinates.subject,
            "predicate": coordinates.predicate,
            "parameters": dict(coordinates.parameters),
            "artifact_digests": dict(coordinates.artifact_digests),
        }
    )
    bounds = canonical_json_bytes(dict(coordinates.evidence_bounds))
    return VstdDerivedSubjectBinding(
        draft_revision=DRAFT_REVISION,
        mapping_version=VSTD_MAPPING_VERSION,
        subject=subject_text(vstd_value(coordinates)),
        claim_coordinate_sha256=hashlib.sha256(coordinate).hexdigest(),
        evidence_bounds_sha256=hashlib.sha256(bounds).hexdigest(),
    )


def compare_vstd_binding(
    coordinates: VstdCoordinates,
    observed: Mapping[str, Any] | None,
) -> DerivedSubjectComparison:
    """Compare the complete experimental VSTD binding without upgrading gaps."""

    if observed is None:
        return DerivedSubjectComparison.NOT_ESTABLISHED
    parsed = VstdDerivedSubjectBinding.from_dict(observed)
    if (
        parsed.draft_revision != DRAFT_REVISION
        or parsed.mapping_version != VSTD_MAPPING_VERSION
    ):
        return DerivedSubjectComparison.NOT_ESTABLISHED
    if parsed == derive_vstd_subject_binding(coordinates):
        return DerivedSubjectComparison.MATCH
    return DerivedSubjectComparison.NO_MATCH
