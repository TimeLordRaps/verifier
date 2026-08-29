"""Terminology: Verifier Standard (VSTD).

Target-neutral VSTD-DATA receipt validation and mechanism replay."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from verifier.core.checker import VerificationVerdict
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import compute_canonical_digest
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    CompletenessMetrics,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)
from verifier.data.assurance import AssuranceFlowError, AssuranceLedger
from verifier.data.policy import ProvenancePolicyVerifier
from verifier.data.receipt import (
    DataIndependentAudit,
    DatasetSpec,
    VstdDataReceipt,
    reproduce_data_receipt,
    validate_data_receipt,
)
from verifier.runtime.public_cli import _inspect_data_receipt, main


def _receipt() -> VstdDataReceipt:
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            artifact_id="artifact:input",
            label="declared input",
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="0" * 64,
            metadata_digest="1" * 64,
            provenance_digest="2" * 64,
            byte_size=0,
            record_count=0,
            mime_type="application/octet-stream",
            storage_uris=(),
            status=ArtifactStatus.UNKNOWN,
        )
    )
    provenance = ProvenanceRecord(
        target_name="public-test",
        portable_repository_id="example.invalid/public-test",
        local_repository_path=".",
        git=GitProvenance(
            commit_sha="0" * 40,
            branch="main",
            is_dirty=False,
            dirty_files=(),
            remote_origin="",
            untracked_files=(),
        ),
        runtime=RuntimeEnvironment(
            python_version="3.12",
            platform_system="test",
            platform_release="test",
            platform_machine="test",
            python_implementation="CPython",
            hostname_masked="test",
        ),
        captured_at_utc="2026-08-20T00:00:00+00:00",
        command_executed="test",
        source_file_hashes={},
    )
    return VstdDataReceipt(
        schema_version="VSTD-DATA-0.1",
        receipt_id="VFY-DATA-PUBLIC-TEST",
        dataset_spec=DatasetSpec(
            dataset_id="dataset:test",
            title="Public test",
            description="Target-neutral receipt fixture.",
            target_artifact_id="artifact:input",
            status="IMPLEMENTED_UNVALIDATED",
            falsification_condition="the stable receipt digest changes",
            last_verified="2026-08-20",
        ),
        hypergraph=graph,
        completeness_metrics=CompletenessMetrics(
            source_coverage=0.0,
            transformation_coverage=0.0,
            content_integrity=1.0,
            license_coverage=0.0,
            contributor_coverage=0.0,
            lineage_depth=0,
            overall_completeness=0.25,
        ),
        policy_evaluations=[],
        independent_audit=DataIndependentAudit(
            overall_verdict=VerificationVerdict.INDETERMINATE,
            acyclic_hypergraph=True,
            integrity_passed=True,
            root_sources_count=1,
            terminal_outputs_count=1,
            transformations_count=0,
            trusted_computing_base={"runtime": "python-stdlib"},
            audit_notes=["The source origin remains UNKNOWN."],
        ),
        provenance=provenance,
        reproducibility={"highest_demonstrated_level": "CONTENT_IDENTICAL"},
    )


def _rehash(payload: dict) -> None:
    provenance = payload["provenance"]
    payload["canonical_digest"] = compute_canonical_digest(
        {
            "schema_version": payload["schema_version"],
            "receipt_id": payload["receipt_id"],
            "dataset_spec": payload["dataset_spec"],
            "hypergraph": payload["hypergraph"],
            "completeness_metrics": payload["completeness_metrics"],
            "policy_evaluations": payload["policy_evaluations"],
            "independent_audit": payload["independent_audit"],
            "provenance_stable": {
                "target_name": provenance["target_name"],
                "portable_repository_id": provenance["portable_repository_id"],
                "git_commit_sha": provenance["git"]["commit_sha"],
                "git_branch": provenance["git"]["branch"],
                "git_is_dirty": provenance["git"]["is_dirty"],
                "runtime_python_version": provenance["runtime"]["python_version"],
            },
            "reproducibility": payload["reproducibility"],
        }
    )


def test_public_data_receipt_round_trip(tmp_path: Path, capsys) -> None:
    _receipt().save_to_directory(tmp_path)
    assert validate_data_receipt(tmp_path) == 0
    assert "[VALIDATION OK]" in capsys.readouterr().out
    assert reproduce_data_receipt(tmp_path) == 0


def test_graph_validate_and_inspect_honor_json(tmp_path: Path, capsys) -> None:
    _receipt().save_to_directory(tmp_path)

    for command in ("validate", "inspect"):
        assert main([command, str(tmp_path), "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["command"] == command
        assert result["receipt_kind"] == "vstd_graph"
        assert result["result"] == "COMPLETED"
        assert result["exit_code"] == 0


def test_actorless_independence_upgrade_is_rejected_and_never_displayed(
    tmp_path: Path, capsys
) -> None:
    receipt_path = _receipt().save_to_directory(tmp_path)
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["independent_audit"]["independence_basis"][
        "independently_verified"
    ] = True
    _rehash(payload)
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    assert _inspect_data_receipt(tmp_path) == 0
    assert "Independence:     NOT_DEMONSTRATED" in capsys.readouterr().out
    assert main(["validate", str(tmp_path)]) == 1
    assert "no actor/execution evidence-binding validator" in capsys.readouterr().err


def test_self_promoted_independence_with_arbitrary_references_is_rejected(
    tmp_path: Path, capsys
) -> None:
    receipt_path = _receipt().save_to_directory(tmp_path)
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    basis = payload["independent_audit"]["independence_basis"]
    basis.update(
        {
            "actor_independence": "EVIDENCED",
            "implementation_separation": "EVIDENCED",
            "runtime_separation": "EVIDENCED",
            "evidence": ["receipt:producer", "receipt:checker"],
            "independently_verified": True,
        }
    )
    _rehash(payload)
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    assert main(["validate", str(tmp_path)]) == 1
    errors = capsys.readouterr().err
    assert "no actor/execution evidence-binding validator" in errors
    assert "no stronger than DECLARED" in errors
    assert main(["inspect", str(tmp_path)]) == 0
    inspection = capsys.readouterr().out
    assert "Independence:     NOT_DEMONSTRATED" in inspection
    assert "Independence:     EVIDENCED" not in inspection


def test_public_data_receipt_tamper_fails(tmp_path: Path) -> None:
    receipt_path = _receipt().save_to_directory(tmp_path)
    receipt_path.write_text(receipt_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    # Whitespace does not alter parsed stable content, so change a stable field too.
    payload = receipt_path.read_text(encoding="utf-8").replace("public-test", "tampered", 1)
    receipt_path.write_text(payload, encoding="utf-8")
    assert validate_data_receipt(tmp_path) == 1


def test_missing_artifact_status_defaults_to_unknown() -> None:
    artifact = ArtifactNode(
        artifact_id="artifact:unspecified",
        label="unspecified status",
        artifact_type=ArtifactType.RAW_SOURCE_FILE,
        content_digest="a" * 64,
    )
    assert artifact.status == ArtifactStatus.UNKNOWN


def test_duplicate_graph_identifier_cannot_replace_recorded_evidence() -> None:
    graph = ProvenanceHypergraph()
    original = ArtifactNode(
        artifact_id="artifact:duplicate",
        label="original",
        artifact_type=ArtifactType.RAW_SOURCE_FILE,
        content_digest="a" * 64,
    )
    graph.add_artifact(original)

    with pytest.raises(ValueError, match="duplicate graph identifier"):
        graph.add_artifact(
            ArtifactNode(
                artifact_id="artifact:duplicate",
                label="replacement",
                artifact_type=ArtifactType.RAW_SOURCE_FILE,
                content_digest="b" * 64,
            )
        )

    assert graph.artifacts["artifact:duplicate"] is original


def test_artifact_and_transformation_identifiers_are_globally_disjoint() -> None:
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            artifact_id="shared:id",
            label="artifact",
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="a" * 64,
        )
    )
    collision = TransformationHyperedge(
        transformation_id="shared:id",
        label="transformation",
        transformation_type=TransformationType.EVALUATION,
        inputs=(HyperedgePort("shared:id", "INPUT"),),
        outputs=(HyperedgePort("shared:id", "OUTPUT"),),
        software_provenance={},
        parameters={},
        execution_environment={},
    )
    with pytest.raises(ValueError, match="identifiers must be disjoint"):
        graph.add_transformation(collision)

    reverse = ProvenanceHypergraph()
    reverse.add_transformation(collision)
    with pytest.raises(ValueError, match="identifiers must be disjoint"):
        reverse.add_artifact(graph.artifacts["shared:id"])

    graph.transformations[collision.transformation_id] = collision
    assert graph.validate_structure()[0] == (
        "artifact and transformation identifiers must be disjoint: shared:id"
    )


def test_frozen_graph_reader_preserves_separate_identifier_namespaces(
    tmp_path: Path, capsys
) -> None:
    artifact = ArtifactNode(
        artifact_id="artifact:input",
        label="input",
        artifact_type=ArtifactType.RAW_SOURCE_FILE,
        content_digest="a" * 64,
    )
    output = ArtifactNode(
        artifact_id="artifact:output",
        label="output",
        artifact_type=ArtifactType.EVALUATION_REPORT,
        content_digest="b" * 64,
    )
    transformation = TransformationHyperedge(
        transformation_id="artifact:input",
        label="historical overlapping identifier",
        transformation_type=TransformationType.EVALUATION,
        inputs=(HyperedgePort("artifact:input", "INPUT"),),
        outputs=(HyperedgePort("artifact:output", "OUTPUT"),),
        software_provenance={},
        parameters={},
        execution_environment={},
    )
    payload = {
        "artifacts": [artifact.to_dict(), output.to_dict()],
        "transformations": [transformation.to_dict()],
        "contributors": [],
        "rights": [],
        "conflicts": [],
    }
    graph_schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "receipts/schema/vstd_graph_receipt.json"
        ).read_text()
    )["properties"]["hypergraph"]
    Draft202012Validator(graph_schema).validate(payload)

    restored = ProvenanceHypergraph.from_dict(payload)
    assert restored.to_dict() == payload
    assert restored.validate_structure(
        allow_legacy_identifier_overlap=True
    ) == []
    assert restored.validate_structure()[0] == (
        "artifact and transformation identifiers must be disjoint: artifact:input"
    )
    with pytest.raises(ValueError, match="identifiers must be disjoint"):
        ProvenanceHypergraph.from_dict(
            payload, allow_legacy_identifier_overlap=False
        )
    duplicate_artifact = {
        **payload,
        "artifacts": [*payload["artifacts"], artifact.to_dict()],
    }
    with pytest.raises(ValueError, match="duplicate graph identifier"):
        ProvenanceHypergraph.from_dict(duplicate_artifact)
    with pytest.raises(AssuranceFlowError, match="invalid source graph"):
        AssuranceLedger(restored)

    receipt = _receipt()
    receipt.hypergraph = restored
    receipt.completeness_metrics = restored.compute_completeness()
    receipt.independent_audit = replace(
        receipt.independent_audit,
        acyclic_hypergraph=True,
        integrity_passed=True,
        root_sources_count=1,
        terminal_outputs_count=1,
        transformations_count=1,
    )
    receipt.save_to_directory(tmp_path)
    assert validate_data_receipt(tmp_path) == 0
    assert "[VALIDATION OK]" in capsys.readouterr().out
    assert reproduce_data_receipt(tmp_path) == 0


def test_completeness_rejects_non_hex_digest() -> None:
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            artifact_id="artifact:bad-digest",
            label="bad digest",
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="z" * 64,
        )
    )
    assert graph.compute_completeness().content_integrity == 0.0
    assert graph.validate_structure() == [
        "artifact artifact:bad-digest has an invalid content_digest"
    ]


def test_data_receipt_rejects_inflated_coverage_metrics(tmp_path: Path) -> None:
    receipt = _receipt()
    receipt.completeness_metrics = CompletenessMetrics(
        source_coverage=1.0,
        transformation_coverage=1.0,
        content_integrity=1.0,
        license_coverage=1.0,
        contributor_coverage=1.0,
        lineage_depth=99,
        overall_completeness=1.0,
    )
    receipt.save_to_directory(tmp_path)
    assert validate_data_receipt(tmp_path) == 1


def test_data_receipt_rejects_dangling_hyperedge_reference(tmp_path: Path) -> None:
    receipt = _receipt()
    receipt.hypergraph.add_transformation(
        TransformationHyperedge(
            transformation_id="transform:dangling",
            label="dangling input",
            transformation_type=TransformationType.EVALUATION,
            inputs=(HyperedgePort("artifact:missing", "INPUT"),),
            outputs=(HyperedgePort("artifact:input", "OUTPUT"),),
            software_provenance={"script": "evaluate.py"},
            parameters={},
            execution_environment={},
        )
    )
    receipt.completeness_metrics = receipt.hypergraph.compute_completeness()
    receipt.independent_audit = DataIndependentAudit(
        overall_verdict=VerificationVerdict.INDETERMINATE,
        acyclic_hypergraph=False,
        integrity_passed=True,
        root_sources_count=0,
        terminal_outputs_count=1,
        transformations_count=1,
        trusted_computing_base={"runtime": "python-stdlib"},
        audit_notes=["The input reference is missing."],
    )
    receipt.save_to_directory(tmp_path)
    assert validate_data_receipt(tmp_path) == 1


def test_no_revoked_policy_does_not_relabel_unknown_as_valid() -> None:
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            artifact_id="artifact:unknown",
            label="unknown root",
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="a" * 64,
        )
    )

    narrow = ProvenancePolicyVerifier.verify_no_revoked_ancestors(
        graph, "artifact:unknown"
    )
    fail_closed = ProvenancePolicyVerifier.verify_all_ancestors_valid(
        graph, "artifact:unknown"
    )

    assert narrow.passed is True
    assert "does not establish" in narrow.explanation
    assert fail_closed.passed is False
    assert fail_closed.verdict == VerificationVerdict.FALSIFIED
