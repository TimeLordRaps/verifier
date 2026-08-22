from __future__ import annotations

from dataclasses import replace
import json

import pytest

from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    ProvenanceHypergraph,
)
from verifier.data.policy import ProvenancePolicyVerifier
from verifier.hardware.emulator import VirtualVSTDAccelerator
from verifier.hardware.adapters.provider import normalize_provider_evidence, sign_provider_fixture
from verifier.hardware.models import (
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    ExecutionIdentity,
    WorkloadIdentity,
)
from verifier.hardware.provenance import HardwareProvenanceError, attach_vstd3_receipt


KEY = b"vstd3-provenance-test-key-32bytes"
PROVIDER_KEY = b"vstd3-provider-test-key-32bytes"


def _receipt():
    device = VirtualVSTDAccelerator("provenance-device", "1.0", KEY)
    device.configure_partitions(())
    device.boot(boot_id="boot", timestamp="2026-08-21T19:00:00Z")
    challenge = device.issue_challenge(
        challenge_id="challenge",
        nonce=b"provenance-nonce",
        issued_at="2026-08-21T19:00:01Z",
        expires_at="2026-08-21T20:00:00Z",
        verifier_id="verifier",
    )
    device.attest(challenge)
    execution = ExecutionIdentity(
        "execution",
        WorkloadIdentity("workload", executable_digest="1" * 64),
        ("logical:partition:provenance-device:whole",),
        device.current_topology_snapshot_id,
        "2026-08-21T19:00:02Z",
    )
    device.submit_execution(execution, timestamp="2026-08-21T19:00:02Z")
    device.observe_execution(
        "execution",
        (
            AccountingQuantity(
                "operations",
                "100",
                "operations",
                AccountingMethod.FIRMWARE_COUNTER,
                device.evidence_source_id,
                "virtual counter",
                AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        timestamp="2026-08-21T19:00:03Z",
    )
    device.complete_execution("execution", timestamp="2026-08-21T19:00:04Z")
    receipt = device.build_receipt(receipt_id="hardware-run", created_at="2026-08-21T19:00:05Z")
    receipt.provenance_artifact_ids = ("model-output",)
    receipt.compute_and_set_digest()
    return device, receipt


def test_hardware_evidence_composes_with_existing_graph_and_blast_radius() -> None:
    device, receipt = _receipt()
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            "model-output",
            "Model output",
            ArtifactType.MODEL,
            "9" * 64,
            status=ArtifactStatus.VALID,
        )
    )
    binding = attach_vstd3_receipt(
        graph,
        receipt,
        key_resolver=lambda key_id: KEY if key_id == device.key_id else None,
    )

    assert binding.validation.valid
    assert graph.validate_structure() == []
    assert graph.verify_acyclicity()
    source_id = f"hardware-source:{device.evidence_source_id}"
    blast = set(graph.blast_radius(source_id))
    assert "hardware-identity:physical:provenance-device" in blast
    assert "hardware-execution:execution" in blast
    assert binding.receipt_artifact_id in blast
    assert "model-output" in blast

    graph.artifacts[source_id] = replace(graph.artifacts[source_id], status=ArtifactStatus.REVOKED)
    verdict = ProvenancePolicyVerifier.verify_no_revoked_ancestors(graph, "model-output")
    assert not verdict.passed


def test_failed_hardware_attachment_is_transactional() -> None:
    _, receipt = _receipt()
    graph = ProvenanceHypergraph()
    graph.add_artifact(ArtifactNode("model-output", "Output", ArtifactType.MODEL, "9" * 64))
    before = graph.to_dict()

    with pytest.raises(HardwareProvenanceError, match="failed validation"):
        attach_vstd3_receipt(graph, receipt)
    assert graph.to_dict() == before


def test_missing_declared_output_is_rejected_without_partial_mutation() -> None:
    device, receipt = _receipt()
    receipt.provenance_artifact_ids = ("does-not-exist",)
    receipt.compute_and_set_digest()
    graph = ProvenanceHypergraph()

    with pytest.raises(HardwareProvenanceError, match="missing provenance artifacts"):
        attach_vstd3_receipt(
            graph,
            receipt,
            key_resolver=lambda key_id: KEY if key_id == device.key_id else None,
        )
    assert graph.to_dict() == {
        "artifacts": [],
        "transformations": [],
        "contributors": [],
        "rights": [],
    }


def test_provider_evidence_is_a_separate_provenance_dimension() -> None:
    device, receipt = _receipt()
    payload = sign_provider_fixture(
        {
            "schema_version": "VSTD3-PROVIDER-EVIDENCE-1.0",
            "evidence_id": "provider-allocation",
            "provider": "example-provider",
            "resource_id": "resource-0",
            "issued_at": "2026-08-21T19:00:01Z",
            "expires_at": "2026-08-21T20:00:00Z",
            "claims": {"allocated": True},
            "key_id": "provider-key",
            "hardware_evidence_refs": [device.evidence_source_id],
        },
        PROVIDER_KEY,
    )
    provider_evidence, provider_source = normalize_provider_evidence(
        json.dumps(payload, sort_keys=True).encode(), verification_key=PROVIDER_KEY
    )
    receipt.evidence_sources = (*receipt.evidence_sources, provider_source)
    receipt.provider_evidence = (provider_evidence,)
    receipt.compute_and_set_digest()

    graph = ProvenanceHypergraph()
    graph.add_artifact(ArtifactNode("model-output", "Output", ArtifactType.MODEL, "9" * 64))
    binding = attach_vstd3_receipt(
        graph,
        receipt,
        key_resolver=lambda key_id: {
            device.key_id: KEY,
            "provider-key": PROVIDER_KEY,
        }.get(key_id),
    )
    provider_artifact = graph.artifacts["provider-evidence:provider-allocation"]
    assert provider_artifact.artifact_type is ArtifactType.PROVIDER_EVIDENCE
    assert provider_artifact.attributes["verification_state"] == "VERIFIED"
    assert binding.receipt_artifact_id in graph.blast_radius(
        f"hardware-source:{provider_source.source_id}"
    )
