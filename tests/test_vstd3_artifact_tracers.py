"""Artifact tracer tests. Terminology: identifier (ID)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from verifier.hardware.canonical import StrictDecodingError
from verifier.hardware.tracers import (
    ArtifactTraceBinding,
    HardwareRuntimeCoordinate,
    TraceAction,
    TraceStatus,
    build_hardware_runtime_coordinate,
    issue_artifact_trace,
    verify_artifact_trace,
)
from verifier.hardware.emulator import VirtualVSTDAccelerator
from verifier.hardware.models import ExecutionIdentity, WorkloadIdentity


KEY = b"artifact-trace-test-key-material-32"


class FixtureCarrier:
    """Visible test carrier; not a production steganographic mechanism."""

    carrier_id = "test-visible-suffix-carrier"
    prefix = b"\x00vstd-trace-test\x00"

    def embed(self, artifact: bytes, marker: bytes) -> bytes:
        return artifact + self.prefix + marker

    def extract(self, artifact: bytes) -> bytes | None:
        offset = artifact.rfind(self.prefix)
        if offset < 0:
            return None
        return artifact[offset + len(self.prefix) :]


class UnavailableExtractionCarrier(FixtureCarrier):
    def extract(self, artifact: bytes) -> bytes | None:
        return None


class MarkerDroppingCarrier(FixtureCarrier):
    def embed(self, artifact: bytes, _marker: bytes) -> bytes:
        return artifact


class ExtractionFailingCarrier(FixtureCarrier):
    def extract(self, _artifact: bytes) -> bytes | None:
        raise RuntimeError("extraction offline")


class FixedEntropy:
    provider_id = "test-fixed-entropy"

    def __init__(self, marker: bytes = b"m" * 32) -> None:
        self.marker = marker

    def token_bytes(self, length: int) -> bytes:
        assert length == 32
        return self.marker


def _coordinate(seed: str = "1") -> HardwareRuntimeCoordinate:
    return HardwareRuntimeCoordinate(
        receipt_digest=seed * 64,
        execution_identity_digest="2" * 64,
        topology_snapshot_digest="3" * 64,
        logical_identity_digests=("4" * 64,),
        physical_identity_digests=("5" * 64,),
        runtime_measurement_digests=("6" * 64,),
    )


def _issue(*, entropy: FixedEntropy | None = None):
    return issue_artifact_trace(
        b"artifact payload",
        _coordinate(),
        carrier=FixtureCarrier(),
        entropy_provider=entropy or FixedEntropy(),
        key_id="trace-key-1",
        key=KEY,
    )


def test_round_trip_matches_exact_post_embedding_bytes_and_coordinates() -> None:
    traced, binding = _issue()

    result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda key_id: KEY if key_id == "trace-key-1" else None,
    )

    assert result.status is TraceStatus.MATCH
    assert result.recommended_action is TraceAction.NONE
    assert result.reason_codes == ()
    assert "natural person" in result.prohibited_inference


def test_artifact_or_coordinate_change_mismatches_and_recommends_quarantine() -> None:
    traced, binding = _issue()

    changed_artifact = bytearray(traced)
    changed_artifact[0] ^= 1
    artifact_result = verify_artifact_trace(
        bytes(changed_artifact),
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: KEY,
    )
    coordinate_result = verify_artifact_trace(
        traced,
        binding,
        _coordinate("a"),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: KEY,
    )

    assert artifact_result.status is TraceStatus.MISMATCH
    assert "ARTIFACT_DIGEST_MISMATCH" in artifact_result.reason_codes
    assert coordinate_result.status is TraceStatus.MISMATCH
    assert "COORDINATE_MISMATCH" in coordinate_result.reason_codes
    assert artifact_result.recommended_action is TraceAction.QUARANTINE_FOR_REVIEW
    assert coordinate_result.recommended_action is TraceAction.QUARANTINE_FOR_REVIEW


def test_missing_marker_or_key_returns_unknown_without_guessing() -> None:
    traced, binding = _issue()

    marker_result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=UnavailableExtractionCarrier(),
        key_resolver=lambda _: KEY,
    )
    key_result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: None,
    )

    assert marker_result.status is TraceStatus.UNKNOWN
    assert "MARKER_UNAVAILABLE" in marker_result.reason_codes
    assert key_result.status is TraceStatus.UNKNOWN
    assert "KEY_UNAVAILABLE" in key_result.reason_codes
    assert marker_result.recommended_action is TraceAction.QUARANTINE_FOR_REVIEW
    assert key_result.recommended_action is TraceAction.QUARANTINE_FOR_REVIEW


def test_unauthenticated_sidecar_cannot_force_artifact_mismatch() -> None:
    traced, binding = _issue()
    changed_artifact = bytearray(traced)
    changed_artifact[0] ^= 1

    result = verify_artifact_trace(
        bytes(changed_artifact),
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: None,
    )

    assert result.status is TraceStatus.UNKNOWN
    assert result.reason_codes == ("KEY_UNAVAILABLE",)


def test_key_resolver_exception_returns_unknown() -> None:
    traced, binding = _issue()

    def unavailable_resolver(_: str) -> bytes | None:
        raise RuntimeError("key service offline")

    result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=unavailable_resolver,
    )

    assert result.status is TraceStatus.UNKNOWN
    assert result.reason_codes == ("KEY_RESOLVER_UNAVAILABLE",)


def test_wrong_key_or_carrier_mismatches() -> None:
    traced, binding = _issue()
    wrong_key = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: b"wrong-key-material-that-is-long-enough",
    )

    other_carrier = FixtureCarrier()
    other_carrier.carrier_id = "other-carrier"
    wrong_carrier = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=other_carrier,
        key_resolver=lambda _: KEY,
    )

    assert wrong_key.status is TraceStatus.MISMATCH
    assert "BINDING_AUTHENTICATION_MISMATCH" in wrong_key.reason_codes
    assert wrong_carrier.status is TraceStatus.MISMATCH
    assert "CARRIER_ID_MISMATCH" in wrong_carrier.reason_codes


def test_malformed_extracted_marker_or_key_material_returns_unknown() -> None:
    traced, binding = _issue()
    malformed_carrier = FixtureCarrier()
    malformed_carrier.extract = lambda _: "x" * 32  # type: ignore[method-assign,return-value]

    marker_result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=malformed_carrier,
        key_resolver=lambda _: KEY,
    )
    key_result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: b"short",
    )

    assert marker_result.status is TraceStatus.UNKNOWN
    assert marker_result.reason_codes == ("MARKER_INVALID",)
    assert key_result.status is TraceStatus.UNKNOWN
    assert key_result.reason_codes == ("KEY_MATERIAL_INVALID",)


def test_binding_serialization_excludes_key_and_raw_marker_and_is_strict() -> None:
    _, binding = _issue()
    payload = binding.to_dict()
    serialized = binding.canonical_bytes()

    assert "key" not in payload
    assert "marker" not in payload
    assert KEY not in serialized
    assert b"m" * 32 not in serialized

    payload["unknown"] = "forbidden"
    with pytest.raises(StrictDecodingError, match="unknown fields"):
        ArtifactTraceBinding.from_dict(payload)


def test_issuance_rejects_bad_entropy_or_key_before_returning_artifact() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _issue(entropy=FixedEntropy(b"short"))
    with pytest.raises(ValueError, match="at least 32 bytes"):
        issue_artifact_trace(
            b"artifact payload",
            _coordinate(),
            carrier=FixtureCarrier(),
            entropy_provider=FixedEntropy(),
            key_id="trace-key-1",
            key=b"short",
        )


def test_repeated_issuance_can_bind_distinct_markers_without_disclosing_them() -> None:
    traced_a, binding_a = _issue(entropy=FixedEntropy(b"a" * 32))
    traced_b, binding_b = _issue(entropy=FixedEntropy(b"b" * 32))

    assert traced_a != traced_b
    assert binding_a.artifact_sha256 != binding_b.artifact_sha256
    assert binding_a.binding_mac_b64 != binding_b.binding_mac_b64


def test_coordinate_builder_binds_valid_receipt_execution_topology_and_identities() -> None:
    device = VirtualVSTDAccelerator("trace-device", "1.0", KEY)
    device.configure_partitions(())
    device.boot(boot_id="boot", timestamp="2026-09-07T12:00:00Z")
    challenge = device.issue_challenge(
        challenge_id="challenge",
        nonce=b"trace-nonce",
        issued_at="2026-09-07T12:00:01Z",
        expires_at="2026-09-07T13:00:00Z",
        verifier_id="verifier",
    )
    device.attest(challenge)
    execution = ExecutionIdentity(
        "execution",
        WorkloadIdentity("workload", executable_digest="7" * 64),
        ("logical:partition:trace-device:whole",),
        device.current_topology_snapshot_id,
        "2026-09-07T12:00:02Z",
    )
    device.submit_execution(execution, timestamp="2026-09-07T12:00:02Z")
    device.complete_execution("execution", timestamp="2026-09-07T12:00:03Z")
    receipt = device.build_receipt(receipt_id="trace-receipt", created_at="2026-09-07T12:00:04Z")

    coordinate = build_hardware_runtime_coordinate(
        receipt,
        "execution",
        key_resolver=lambda key_id: KEY if key_id == device.key_id else None,
    )

    assert coordinate.receipt_digest == receipt.canonical_digest
    assert coordinate.execution_identity_digest == execution.canonical_hash()
    assert len(coordinate.logical_identity_digests) == 1
    assert len(coordinate.physical_identity_digests) == 1
    assert coordinate.runtime_measurement_digests


def test_trace_match_never_establishes_actor_identity_or_authorizes_action() -> None:
    traced, binding = _issue()
    result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: KEY,
    )

    assert result.status is TraceStatus.MATCH
    assert result.recommended_action is TraceAction.NONE
    for prohibited in ("authorship", "malicious intent", "guilt", "authorization"):
        assert prohibited in result.prohibited_inference
    assert not hasattr(result, "actor_id")
    assert not hasattr(binding, "actor_id")


def test_binding_validation_rejects_invalid_digests() -> None:
    _, binding = _issue()
    with pytest.raises(ValueError, match="artifact_sha256"):
        replace(binding, artifact_sha256="not-a-digest")


@pytest.mark.parametrize(
    ("field_name", "tampered"),
    [
        ("artifact_sha256", lambda _: "0" * 64),
        ("artifact_size_bytes", lambda binding: binding.artifact_size_bytes + 1),
        ("coordinate", lambda _: _coordinate("a")),
        ("carrier_id", lambda _: "other-carrier"),
        ("entropy_provider_id", lambda _: "other-entropy-provider"),
        ("key_id", lambda _: "trace-key-2"),
        ("limitations", lambda binding: binding.limitations + ("an added limitation",)),
    ],
)
def test_every_sidecar_field_is_authenticated_rather_than_only_compared(field_name, tampered) -> None:
    traced, binding = _issue()
    forged = replace(binding, **{field_name: tampered(binding)})

    result = verify_artifact_trace(
        traced,
        forged,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: KEY,
    )

    assert result.status is TraceStatus.MISMATCH
    assert result.reason_codes == ("BINDING_AUTHENTICATION_MISMATCH",)
    assert result.recommended_action is TraceAction.QUARANTINE_FOR_REVIEW


def test_marker_reported_by_the_carrier_is_authenticated_not_trusted() -> None:
    traced, binding = _issue()
    substituted = FixtureCarrier()
    substituted.extract = lambda _: b"z" * 32  # type: ignore[method-assign]

    result = verify_artifact_trace(
        traced,
        binding,
        _coordinate(),
        carrier=substituted,
        key_resolver=lambda _: KEY,
    )

    assert result.status is TraceStatus.MISMATCH
    assert result.reason_codes == ("BINDING_AUTHENTICATION_MISMATCH",)


def test_prefix_extended_artifact_reports_size_and_digest_mismatch() -> None:
    traced, binding = _issue()

    # The suffix carrier still extracts the exact marker, so only the artifact bytes differ.
    result = verify_artifact_trace(
        b"x" + traced,
        binding,
        _coordinate(),
        carrier=FixtureCarrier(),
        key_resolver=lambda _: KEY,
    )

    assert result.status is TraceStatus.MISMATCH
    assert result.reason_codes == ("ARTIFACT_SIZE_MISMATCH", "ARTIFACT_DIGEST_MISMATCH")


@pytest.mark.parametrize(
    ("carrier", "message"),
    [
        (MarkerDroppingCarrier(), "did not preserve the exact marker"),
        (ExtractionFailingCarrier(), "could not re-extract its marker"),
    ],
)
def test_issuance_requires_the_carrier_to_re_extract_the_exact_marker(carrier, message) -> None:
    with pytest.raises(ValueError, match=message):
        issue_artifact_trace(
            b"artifact payload",
            _coordinate(),
            carrier=carrier,
            entropy_provider=FixedEntropy(),
            key_id="trace-key-1",
            key=KEY,
        )
