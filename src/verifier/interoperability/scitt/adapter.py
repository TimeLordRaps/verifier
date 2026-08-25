"""Terminology: American Standard Code for Information Interchange (ASCII);
Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE);
Internet Engineering Task Force (IETF); JavaScript Object Notation (JSON);
Request for Comments (RFC); Supply Chain Integrity, Transparency, and Trust (SCITT);
Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Strict experimental mapping between VSTD's interlingua and IETF SCITT.

The emitted registration template is a deterministic *input* to a native
SCITT/COSE implementation.  It is not CBOR, COSE_Sign1, a signature, a COSE
Receipt, or proof that a Transparency Service registered anything.  Likewise,
the reverse adapter accepts only the normalized output of an external SCITT
verifier.  It never verifies COSE itself.

VSTD does not replace SCITT or the payload's native verifier.  It provides the
portable claim/result language through which those orchestrated substrates are
composed while their native semantics remain visible.

The central invariant is monotonicity of epistemic strength: registration or
receipt integrity cannot manufacture a VSTD computational verdict.  A composed
PASS requires both a native VSTD PASS and a current, verified SCITT registration
for the exact payload.  Every other state is preserved or lowers the result.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Sequence


MAPPING_VERSION = "0.1"
EXPERIMENTAL_PROFILE = "vstd-scitt-interop-experimental-0.1"
EXPERIMENTAL_CONTENT_TYPE = "application/vnd.verifier.vstd-receipt+json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VSTD_PASS = frozenset({"PASS"})
_VSTD_FAIL = frozenset({"FAIL", "FALSIFIED"})
_VSTD_UNKNOWN = frozenset({"UNKNOWN", "INDETERMINATE", "UNSUPPORTED"})


class InteropError(ValueError):
    """Raised when a mapping is incomplete, ambiguous, or unsupported."""


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize experimental mapping objects deterministically.

    This deliberately matches VSTD's existing sorted, compact, ASCII JSON
    rules, while remaining a mapping-level serializer rather than a claim that
    JSON is SCITT's COSE wire format.
    """

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InteropError(f"value is not canonical-JSON serializable: {exc}") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise InteropError(f"{label} must be a lowercase SHA-256 digest")
    normalized = value.removeprefix("sha256:")
    if not _SHA256.fullmatch(normalized):
        raise InteropError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InteropError(f"{label} must be a non-empty string")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise InteropError(
            f"{label} keys mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _string_map(value: Mapping[str, Any], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, item in value.items():
        result[_nonempty(key, f"{label} key")] = _nonempty(
            item, f"{label}[{key!r}]"
        )
    return dict(sorted(result.items()))


@dataclass(frozen=True)
class VstdCoordinates:
    """Loss-sensitive projection of the VSTD semantics carried in SCITT.

    The full native receipt is embedded as the payload.  This projection makes
    the coordinates a SCITT registration policy or relying-party tool is most
    likely to inspect explicit without pretending one generic adapter can infer
    every VSTD receipt family's semantics.
    """

    receipt_id: str
    schema_version: str
    claim_id: str
    subject: str
    predicate: str
    parameters: Mapping[str, str]
    native_result: str
    native_canonical_digest: str
    evidence_bounds: Mapping[str, int]
    artifact_digests: Mapping[str, str]
    provenance_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "receipt_id",
            "schema_version",
            "claim_id",
            "subject",
            "predicate",
            "native_result",
        ):
            _nonempty(getattr(self, name), name)
        object.__setattr__(
            self,
            "native_canonical_digest",
            _digest(self.native_canonical_digest, "native_canonical_digest"),
        )
        params = _string_map(self.parameters, "parameters")
        object.__setattr__(self, "parameters", MappingProxyType(params))

        bounds: dict[str, int] = {}
        for key, value in self.evidence_bounds.items():
            key = _nonempty(key, "evidence_bounds key")
            if type(value) is not int or value < 0:
                raise InteropError(
                    f"evidence_bounds[{key!r}] must be a non-negative integer"
                )
            bounds[key] = value
        object.__setattr__(
            self, "evidence_bounds", MappingProxyType(dict(sorted(bounds.items())))
        )

        artifacts = {
            _nonempty(key, "artifact_digests key"): _digest(
                value, f"artifact_digests[{key!r}]"
            )
            for key, value in self.artifact_digests.items()
        }
        if not artifacts:
            raise InteropError("at least one artifact digest is required")
        object.__setattr__(
            self, "artifact_digests", MappingProxyType(dict(sorted(artifacts.items())))
        )
        refs = tuple(_nonempty(item, "provenance reference") for item in self.provenance_references)
        if len(set(refs)) != len(refs):
            raise InteropError("provenance_references must be unique")
        object.__setattr__(self, "provenance_references", refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "claim_coordinate": {
                "subject": self.subject,
                "predicate": self.predicate,
                "parameters": dict(self.parameters),
            },
            "native_result": self.native_result,
            "native_canonical_digest": self.native_canonical_digest,
            "evidence_bounds": dict(self.evidence_bounds),
            "artifact_digests": dict(self.artifact_digests),
            "provenance_references": list(self.provenance_references),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VstdCoordinates":
        _exact_keys(
            value,
            {
                "receipt_id",
                "schema_version",
                "claim_id",
                "claim_coordinate",
                "native_result",
                "native_canonical_digest",
                "evidence_bounds",
                "artifact_digests",
                "provenance_references",
            },
            "vstd_coordinates",
        )
        coordinate = value["claim_coordinate"]
        if not isinstance(coordinate, Mapping):
            raise InteropError("claim_coordinate must be an object")
        _exact_keys(
            coordinate, {"subject", "predicate", "parameters"}, "claim_coordinate"
        )
        parameters = coordinate["parameters"]
        bounds = value["evidence_bounds"]
        artifacts = value["artifact_digests"]
        refs = value["provenance_references"]
        if not isinstance(parameters, Mapping):
            raise InteropError("claim_coordinate.parameters must be an object")
        if not isinstance(bounds, Mapping):
            raise InteropError("evidence_bounds must be an object")
        if not isinstance(artifacts, Mapping):
            raise InteropError("artifact_digests must be an object")
        if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
            raise InteropError("provenance_references must be an array of strings")
        return cls(
            receipt_id=value["receipt_id"],
            schema_version=value["schema_version"],
            claim_id=value["claim_id"],
            subject=coordinate["subject"],
            predicate=coordinate["predicate"],
            parameters=parameters,
            native_result=value["native_result"],
            native_canonical_digest=value["native_canonical_digest"],
            evidence_bounds=bounds,
            artifact_digests=artifacts,
            provenance_references=tuple(refs),
        )


@dataclass(frozen=True)
class VstdScittPayload:
    """Experimental application payload for carriage in a SCITT statement."""

    receipt: Mapping[str, Any]
    coordinates: VstdCoordinates
    receipt_sha256: str
    mapping_version: str = MAPPING_VERSION
    profile: str = EXPERIMENTAL_PROFILE
    receipt_media_type: str = EXPERIMENTAL_CONTENT_TYPE

    def __post_init__(self) -> None:
        if self.mapping_version != MAPPING_VERSION:
            raise InteropError(f"unsupported mapping version {self.mapping_version!r}")
        if self.profile != EXPERIMENTAL_PROFILE:
            raise InteropError(f"unsupported profile {self.profile!r}")
        if self.receipt_media_type != EXPERIMENTAL_CONTENT_TYPE:
            raise InteropError(
                f"unsupported receipt media type {self.receipt_media_type!r}"
            )
        if not isinstance(self.receipt, Mapping):
            raise InteropError("receipt must be an object")
        _digest(self.receipt_sha256, "receipt_sha256")
        # Break aliases to caller-owned nested dictionaries.  ``to_dict`` also
        # rechecks the digest, so even deliberate mutation through the exposed
        # nested projection fails closed rather than changing signed bytes.
        copied = json.loads(canonical_json_bytes(dict(self.receipt)).decode("utf-8"))
        object.__setattr__(self, "receipt", MappingProxyType(copied))
        self.verify_integrity()

    @classmethod
    def create(
        cls, receipt: Mapping[str, Any], coordinates: VstdCoordinates
    ) -> "VstdScittPayload":
        copied = dict(receipt)
        return cls(
            receipt=copied,
            coordinates=coordinates,
            receipt_sha256=_sha256(canonical_json_bytes(copied)),
        )

    def verify_integrity(self) -> None:
        observed = _sha256(canonical_json_bytes(dict(self.receipt)))
        if observed != self.receipt_sha256:
            raise InteropError("embedded VSTD receipt does not match receipt_sha256")
        for field in ("receipt_id", "schema_version"):
            native = self.receipt.get(field)
            declared = getattr(self.coordinates, field)
            if native != declared:
                raise InteropError(
                    f"embedded receipt {field} {native!r} does not match "
                    f"declared coordinate {declared!r}"
                )
        native_digest = self.receipt.get("canonical_digest")
        if native_digest is not None:
            if _digest(native_digest, "receipt.canonical_digest") != (
                self.coordinates.native_canonical_digest
            ):
                raise InteropError(
                    "embedded receipt canonical_digest does not match VSTD coordinates"
                )
        elif observed != self.coordinates.native_canonical_digest:
            raise InteropError(
                "embedded receipt full canonical digest does not match VSTD coordinates"
            )

        native_claim_id = self.receipt.get("claim_id")
        if native_claim_id is not None and native_claim_id != self.coordinates.claim_id:
            raise InteropError(
                "embedded receipt claim_id does not match VSTD coordinates"
            )

        binding = self.receipt.get("binding")
        if isinstance(binding, Mapping):
            coordinate = binding.get("coordinate")
            if isinstance(coordinate, Mapping):
                expected = {
                    "subject": self.coordinates.subject,
                    "predicate": self.coordinates.predicate,
                    "parameters": dict(self.coordinates.parameters),
                }
                if dict(coordinate) != expected:
                    raise InteropError(
                        "embedded VSTD binding coordinate does not match mapping coordinate"
                    )
            bounds = binding.get("bounds")
            if isinstance(bounds, Mapping) and dict(bounds) != dict(
                self.coordinates.evidence_bounds
            ):
                raise InteropError(
                    "embedded VSTD evidence bounds do not match mapping coordinates"
                )

        native_result = None
        witness = self.receipt.get("witness")
        if isinstance(witness, Mapping):
            header = witness.get("header")
            if isinstance(header, Mapping):
                native_result = header.get("verdict")
        decision = self.receipt.get("decision")
        if native_result is None and isinstance(decision, Mapping):
            native_result = decision.get("verdict")
        if native_result is not None and native_result != self.coordinates.native_result:
            raise InteropError(
                "embedded VSTD native result does not match mapping coordinates"
            )

    def to_dict(self) -> dict[str, Any]:
        self.verify_integrity()
        return {
            "mapping_version": self.mapping_version,
            "profile": self.profile,
            "receipt_media_type": self.receipt_media_type,
            "receipt_sha256": self.receipt_sha256,
            "vstd_coordinates": self.coordinates.to_dict(),
            "vstd_receipt": dict(self.receipt),
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def payload_sha256(self) -> str:
        return _sha256(self.to_bytes())

    @classmethod
    def from_bytes(cls, value: bytes) -> "VstdScittPayload":
        try:
            decoded = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InteropError(f"SCITT payload is not canonical JSON: {exc}") from exc
        if not isinstance(decoded, Mapping):
            raise InteropError("SCITT payload must be an object")
        if canonical_json_bytes(decoded) != value:
            raise InteropError("SCITT payload bytes are not in canonical form")
        _exact_keys(
            decoded,
            {
                "mapping_version",
                "profile",
                "receipt_media_type",
                "receipt_sha256",
                "vstd_coordinates",
                "vstd_receipt",
            },
            "SCITT payload",
        )
        coordinates = decoded["vstd_coordinates"]
        receipt = decoded["vstd_receipt"]
        if not isinstance(coordinates, Mapping) or not isinstance(receipt, Mapping):
            raise InteropError("vstd_coordinates and vstd_receipt must be objects")
        return cls(
            mapping_version=decoded["mapping_version"],
            profile=decoded["profile"],
            receipt_media_type=decoded["receipt_media_type"],
            receipt_sha256=decoded["receipt_sha256"],
            coordinates=VstdCoordinates.from_dict(coordinates),
            receipt=receipt,
        )


@dataclass(frozen=True)
class ScittRegistrationTemplate:
    """Normalized input for a native RFC 9943/COSE statement producer."""

    issuer: str
    subject: str
    payload: VstdScittPayload

    def __post_init__(self) -> None:
        _nonempty(self.issuer, "issuer")
        _nonempty(self.subject, "subject")
        if self.subject != self.payload.coordinates.subject:
            raise InteropError(
                "SCITT subject must equal the VSTD claim-coordinate subject"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "representation": "normalized-registration-input-not-cose",
            "required_protected_header_projection": {
                "content_type": EXPERIMENTAL_CONTENT_TYPE,
                "issuer": self.issuer,
                "payload_hash_algorithm": "sha-256",
                "subject": self.subject,
                "type": EXPERIMENTAL_PROFILE,
            },
            "payload_sha256": self.payload.payload_sha256(),
            "payload": self.payload.to_dict(),
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


class ScittEvidenceState(str, Enum):
    """Normalized relying-party state; not an IETF registry."""

    REGISTERED = "REGISTERED"
    MISSING = "MISSING"
    STALE = "STALE"
    CONFLICTED = "CONFLICTED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


class VstdVerificationState(str, Enum):
    """Normalized state from a native VSTD checker, not a wire registry."""

    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass(frozen=True)
class VstdVerificationEvidence:
    """Bound output from a native VSTD checker.

    The adapter cannot infer that an embedded receipt was checked merely
    because the receipt declares ``PASS``.  A caller must provide the native
    check state for the exact embedded receipt and retain the checker trust
    coordinates.  This is deliberately symmetric with
    :class:`ScittVerificationEvidence`, which is normalized output from a
    native SCITT verifier rather than a replacement for one.
    """

    state: VstdVerificationState
    receipt_sha256: str
    native_result: str
    checker: str
    verification_profile: str
    reason: str

    def __post_init__(self) -> None:
        try:
            state = VstdVerificationState(self.state)
        except (TypeError, ValueError) as exc:
            raise InteropError(
                f"unsupported VSTD verification state {self.state!r}"
            ) from exc
        object.__setattr__(self, "state", state)
        object.__setattr__(
            self, "receipt_sha256", _digest(self.receipt_sha256, "receipt_sha256")
        )
        for name in ("native_result", "checker", "verification_profile", "reason"):
            _nonempty(getattr(self, name), name)

    def to_dict(self) -> dict[str, str]:
        return {
            "state": self.state.value,
            "receipt_sha256": self.receipt_sha256,
            "native_result": self.native_result,
            "checker": self.checker,
            "verification_profile": self.verification_profile,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VstdVerificationEvidence":
        expected = {
            "state",
            "receipt_sha256",
            "native_result",
            "checker",
            "verification_profile",
            "reason",
        }
        _exact_keys(value, expected, "VSTD verification evidence")
        try:
            state = VstdVerificationState(value["state"])
        except ValueError as exc:
            raise InteropError(
                f"unsupported VSTD verification state {value['state']!r}"
            ) from exc
        return cls(state=state, **{key: value[key] for key in expected - {"state"}})


@dataclass(frozen=True)
class ScittVerificationEvidence:
    """Output supplied by a native SCITT verifier under an explicit policy.

    ``state`` is a local normalized policy result.  RFC 9943 does not define
    this enum, and callers must retain ``native_result`` and ``reason`` so that
    the source verifier's semantics are not erased.
    """

    state: ScittEvidenceState
    statement_sha256: str
    payload_sha256: str
    issuer: str
    subject: str
    signed_statement_verified: bool
    receipt_verified: bool
    verification_profile: str
    registration_policy: str
    transparency_service: str
    vds: str
    native_result: str
    reason: str
    registered_at: str | None = None

    def __post_init__(self) -> None:
        try:
            state = ScittEvidenceState(self.state)
        except (TypeError, ValueError) as exc:
            raise InteropError(f"unsupported SCITT evidence state {self.state!r}") from exc
        object.__setattr__(self, "state", state)
        object.__setattr__(
            self, "statement_sha256", _digest(self.statement_sha256, "statement_sha256")
        )
        object.__setattr__(
            self, "payload_sha256", _digest(self.payload_sha256, "payload_sha256")
        )
        for name in (
            "issuer",
            "subject",
            "verification_profile",
            "registration_policy",
            "transparency_service",
            "vds",
            "native_result",
            "reason",
        ):
            _nonempty(getattr(self, name), name)
        if type(self.signed_statement_verified) is not bool:
            raise InteropError("signed_statement_verified must be boolean")
        if type(self.receipt_verified) is not bool:
            raise InteropError("receipt_verified must be boolean")
        if self.registered_at is not None:
            _nonempty(self.registered_at, "registered_at")
        if self.state is ScittEvidenceState.REGISTERED and not (
            self.signed_statement_verified and self.receipt_verified
        ):
            raise InteropError(
                "REGISTERED requires independently verified statement and receipt"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "statement_sha256": self.statement_sha256,
            "payload_sha256": self.payload_sha256,
            "issuer": self.issuer,
            "subject": self.subject,
            "signed_statement_verified": self.signed_statement_verified,
            "receipt_verified": self.receipt_verified,
            "verification_profile": self.verification_profile,
            "registration_policy": self.registration_policy,
            "transparency_service": self.transparency_service,
            "vds": self.vds,
            "native_result": self.native_result,
            "reason": self.reason,
            "registered_at": self.registered_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScittVerificationEvidence":
        expected = {
            "state",
            "statement_sha256",
            "payload_sha256",
            "issuer",
            "subject",
            "signed_statement_verified",
            "receipt_verified",
            "verification_profile",
            "registration_policy",
            "transparency_service",
            "vds",
            "native_result",
            "reason",
            "registered_at",
        }
        _exact_keys(value, expected, "SCITT verification evidence")
        try:
            state = ScittEvidenceState(value["state"])
        except ValueError as exc:
            raise InteropError(f"unsupported SCITT evidence state {value['state']!r}") from exc
        return cls(state=state, **{key: value[key] for key in expected - {"state"}})


class CompositionStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


@dataclass(frozen=True)
class CompositionResult:
    status: CompositionStatus
    native_vstd_result: str
    native_scitt_result: str
    reason: str
    vstd_receipt_sha256: str
    scitt_statement_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "native_vstd_result": self.native_vstd_result,
            "native_scitt_result": self.native_scitt_result,
            "reason": self.reason,
            "vstd_receipt_sha256": self.vstd_receipt_sha256,
            "scitt_statement_sha256": self.scitt_statement_sha256,
        }


def create_scitt_registration_template(
    receipt: Mapping[str, Any],
    coordinates: VstdCoordinates,
    *,
    issuer: str,
    subject: str,
) -> ScittRegistrationTemplate:
    """Create deterministic inputs for an external SCITT/COSE producer."""

    return ScittRegistrationTemplate(
        issuer=issuer,
        subject=subject,
        payload=VstdScittPayload.create(receipt, coordinates),
    )


def consume_scitt_evidence(
    evidence: ScittVerificationEvidence,
    *,
    expected_payload_sha256: str,
    expected_subject: str,
    accepted_issuers: Sequence[str],
) -> dict[str, Any]:
    """Convert a native SCITT verifier result into bounded VSTD evidence.

    The returned object describes transparency evidence only.  Its
    ``computational_verdict`` is always ``NOT_EVALUATED``.
    """

    expected_digest = _digest(expected_payload_sha256, "expected_payload_sha256")
    accepted = tuple(_nonempty(item, "accepted issuer") for item in accepted_issuers)
    if not accepted:
        raise InteropError("accepted_issuers cannot be empty")

    state = evidence.state
    reason = evidence.reason
    if evidence.payload_sha256 != expected_digest:
        state = ScittEvidenceState.INVALID
        reason = "SCITT statement payload does not bind the expected VSTD payload"
    elif evidence.subject != expected_subject:
        state = ScittEvidenceState.INVALID
        reason = "SCITT subject does not match the VSTD claim subject"
    elif evidence.issuer not in accepted:
        state = ScittEvidenceState.INVALID
        reason = "SCITT issuer is not accepted by the relying-party policy"
    elif not evidence.signed_statement_verified or not evidence.receipt_verified:
        state = ScittEvidenceState.INVALID
        reason = "native SCITT statement or receipt verification did not succeed"

    return {
        "evidence_kind": "SCITT_TRANSPARENCY",
        "normalized_state": state.value,
        "native_scitt_result": evidence.native_result,
        "reason": reason,
        "computational_verdict": "NOT_EVALUATED",
        "trust_coordinates": {
            "accepted_issuers": list(accepted),
            "registration_policy": evidence.registration_policy,
            "transparency_service": evidence.transparency_service,
            "verification_profile": evidence.verification_profile,
            "vds": evidence.vds,
        },
        "statement_sha256": evidence.statement_sha256,
        "payload_sha256": evidence.payload_sha256,
        "registered_at": evidence.registered_at,
    }


def compose_results(
    payload: VstdScittPayload,
    vstd: VstdVerificationEvidence,
    scitt: ScittVerificationEvidence,
    *,
    artifact_digests: Mapping[str, str],
    accepted_issuers: Sequence[str],
) -> CompositionResult:
    """Compose exact VSTD and SCITT results without semantic upgrading."""

    observed_artifacts = {
        _nonempty(key, "artifact_digests key"): _digest(
            value, f"artifact_digests[{key!r}]"
        )
        for key, value in artifact_digests.items()
    }
    transparency = consume_scitt_evidence(
        scitt,
        expected_payload_sha256=payload.payload_sha256(),
        expected_subject=payload.coordinates.subject,
        accepted_issuers=accepted_issuers,
    )
    scitt_state = ScittEvidenceState(transparency["normalized_state"])
    native_vstd = vstd.native_result

    if observed_artifacts != dict(payload.coordinates.artifact_digests):
        status = CompositionStatus.FAIL
        reason = "artifact binding mismatch"
    elif vstd.receipt_sha256 != payload.receipt_sha256:
        status = CompositionStatus.FAIL
        reason = "native VSTD checker result does not bind the embedded receipt"
    elif (
        vstd.state is VstdVerificationState.VERIFIED
        and vstd.native_result != payload.coordinates.native_result
    ):
        status = CompositionStatus.FAIL
        reason = "native VSTD checker result does not match the payload result"
    elif vstd.state is VstdVerificationState.REJECTED:
        status = CompositionStatus.FAIL
        reason = f"native VSTD checker rejected the receipt: {vstd.reason}"
    elif vstd.state is VstdVerificationState.NOT_EVALUATED:
        status = CompositionStatus.UNKNOWN
        reason = "native VSTD receipt was not evaluated"
    elif vstd.state is VstdVerificationState.INDETERMINATE:
        status = CompositionStatus.UNKNOWN
        reason = f"native VSTD checker was unable to decide: {vstd.reason}"
    elif native_vstd in _VSTD_FAIL:
        status = CompositionStatus.FAIL
        reason = "native VSTD verification failed"
    elif scitt_state is ScittEvidenceState.INVALID:
        status = CompositionStatus.FAIL
        reason = transparency["reason"]
    elif native_vstd == CompositionStatus.CONFLICTED.value:
        status = CompositionStatus.CONFLICTED
        reason = "native VSTD evidence is conflicted"
    elif scitt_state is ScittEvidenceState.CONFLICTED:
        status = CompositionStatus.CONFLICTED
        reason = "SCITT evidence graph or relying-party policy reports a conflict"
    elif native_vstd in _VSTD_UNKNOWN:
        status = CompositionStatus.UNKNOWN
        reason = "native VSTD verification is indeterminate or unsupported"
    elif scitt_state is not ScittEvidenceState.REGISTERED:
        status = CompositionStatus.UNKNOWN
        reason = f"SCITT evidence state {scitt_state.value} does not establish a current registration"
    elif native_vstd in _VSTD_PASS:
        status = CompositionStatus.PASS
        reason = "native VSTD PASS and exact current SCITT registration both verified"
    else:
        raise InteropError(
            f"unsupported native VSTD result {native_vstd!r}; refusing to guess"
        )

    return CompositionResult(
        status=status,
        native_vstd_result=native_vstd,
        native_scitt_result=scitt.native_result,
        reason=reason,
        vstd_receipt_sha256=payload.receipt_sha256,
        scitt_statement_sha256=scitt.statement_sha256,
    )
