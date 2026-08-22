from __future__ import annotations

from verifiable.data.models import (
    ArtifactNode,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)


def test_pre_vstd3_hypergraph_values_round_trip_unchanged() -> None:
    graph = ProvenanceHypergraph()
    graph.add_artifact(ArtifactNode("source", "Source", ArtifactType.SHARD, "1" * 64))
    graph.add_artifact(ArtifactNode("model", "Model", ArtifactType.MODEL, "2" * 64))
    graph.add_transformation(
        TransformationHyperedge(
            "train",
            "Train",
            TransformationType.TRAINING,
            inputs=(HyperedgePort("source", "TRAIN_DATA"),),
            outputs=(HyperedgePort("model", "MODEL"),),
            software_provenance={"script": "train.py"},
            parameters={},
            execution_environment={},
        )
    )
    encoded = graph.to_dict()
    decoded = ProvenanceHypergraph.from_dict(encoded)
    assert decoded.to_dict() == encoded
    assert decoded.validate_structure() == []
    assert decoded.blast_radius("source") == ["model"]


def test_hardware_enum_additions_do_not_rename_existing_values() -> None:
    assert ArtifactType.RAW_SOURCE_FILE.value == "RAW_SOURCE_FILE"
    assert ArtifactType.CHECKPOINT.value == "CHECKPOINT"
    assert ArtifactType.MODEL.value == "MODEL"
    assert TransformationType.TRAINING.value == "TRAINING"
    assert TransformationType.QUANTIZATION.value == "QUANTIZATION"
    assert TransformationType.EVALUATION.value == "EVALUATION"
