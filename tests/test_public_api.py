"""Supported Python application programming interface (API) characterization tests."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import verifier


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXPORTS = {
    "AssuranceLedger",
    "ArtifactControlError",
    "ArtifactVerification",
    "BoundProposition",
    "EvidenceBindingError",
    "DecisionCertificate",
    "EvidenceBounds",
    "EvidenceStore",
    "MechanismDecision",
    "MechanismOutcome",
    "ObligationCoordinate",
    "PlatformComparisonResult",
    "PlatformComparisonStatus",
    "ProvenanceHypergraph",
    "ReproducibilityLevel",
    "VerificationSession",
    "VerificationGeometry",
    "VerificationVerdict",
    "VstdReceipt",
    "WitnessBundle",
    "assess_witness_corroboration",
    "build_evidence_bound_graph_level_record",
    "build_evidence_bound_vstd4_receipt",
    "build_vstd5_receipt",
    "capture_run",
    "certificate_from_canonical_bytes",
    "compute_canonical_digest",
    "compare_platform_run_receipts",
    "claim_binding_from_dict",
    "establish_graph_level",
    "establish_vstd4",
    "freeze_artifact",
    "graph_collection_binding_digest",
    "recheck_assurance_log",
    "recheck_evidence_bound_graph_level_record",
    "recheck_evidence_bound_vstd4_receipt",
    "recheck_vstd5_receipt",
    "require_vstd5_entry",
    "seal_artifact",
    "thaw_artifact",
    "thawed_artifact_status",
    "validate_run_receipt",
    "vstd4_depth",
    "verify_frozen_artifact",
}


def test_supported_top_level_exports_are_explicit_and_resolvable() -> None:
    assert set(verifier.__all__) == EXPECTED_EXPORTS
    assert set(verifier._LAZY_EXPORTS) == EXPECTED_EXPORTS
    for name in verifier.__all__:
        assert getattr(verifier, name) is not None


def test_thaw_status_public_api_requires_explicit_parent_evidence_for_establishment() -> None:
    parameters = inspect.signature(verifier.thawed_artifact_status).parameters
    assert tuple(parameters) == (
        "artifact",
        "thaw_record",
        "parent_bundle",
        "expected_artifact_id",
        "expected_key_id",
    )
    assert parameters["parent_bundle"].kind is inspect.Parameter.KEYWORD_ONLY


def test_deprecation_registry_warns_without_replacing_the_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "capture_run"
    monkeypatch.delattr(verifier, name, raising=False)
    monkeypatch.setitem(verifier._API_DEPRECATIONS, name, ("1.3.0", "replacement_name"))

    with pytest.warns(DeprecationWarning, match="deprecated since 1.3.0"):
        resolved = getattr(verifier, name)

    assert resolved is verifier._LAZY_EXPORTS[name] or callable(resolved)


def test_every_declared_deprecation_is_supported_and_release_noted() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for name, (since, replacement) in verifier._API_DEPRECATIONS.items():
        assert name in verifier.__all__
        assert since in changelog
        assert name in changelog
        assert replacement in changelog
