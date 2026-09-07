"""Experimental Verifier Standard (VSTD) topology; JavaScript Object Notation (JSON).

Literal declarations are model variables, not observed switch states. Their bytes
are hashed, but provenance and declared normalization execution remain UNKNOWN.
A tick is one integer logical step; backward-time relations are not physical
retrocausation. TRUST means mechanism-earned forward artifact support; none is issued.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from verifier.data.models import (
    ArtifactNode, ArtifactStatus, ArtifactType, HyperedgePort,
    ProvenanceHypergraph, TransformationHyperedge, TransformationType,
)
from verifier.interoperability.graph_topology import (
    GRAPH_TOPOLOGY_SCHEMA_VERSION, GraphTopologyContract,
    analyze_graph_topology, graph_topology_binding_digest,
)

DECLARATIONS = {"before": b"before\n", "after": b"after\n"}
TRANSFORMATION = "normalize:model"


def build_example() -> tuple[ProvenanceHypergraph, GraphTopologyContract]:
    """Bind two exact declared ports, simultaneous Booleans, and one clock relation."""
    graph = ProvenanceHypergraph()
    for name, payload in DECLARATIONS.items():
        graph.add_artifact(ArtifactNode(
            artifact_id=name, label=f"Symbolic {name} declaration",
            artifact_type=ArtifactType.CONFIG,
            content_digest=hashlib.sha256(payload).hexdigest(), byte_size=len(payload),
            mime_type="text/plain", storage_uris=(f"{name}.txt",),
            status=ArtifactStatus.UNKNOWN,
            attributes={"meaning": "model-variable declaration", "origin": "UNKNOWN"},
        ))
    graph.add_transformation(TransformationHyperedge(
        transformation_id=TRANSFORMATION, label="Declared model normalization",
        transformation_type=TransformationType.NORMALIZATION,
        inputs=(HyperedgePort("before", "state"),),
        outputs=(HyperedgePort("after", "state"),),
        software_provenance={}, parameters={}, execution_environment={}, status="UNKNOWN",
    ))
    contract = GraphTopologyContract.from_dict({
        "schema_version": GRAPH_TOPOLOGY_SCHEMA_VERSION,
        "graph_digest": graph_topology_binding_digest(graph),
        "bindings": [
            {"variable_id": name, "artifact_id": name, "transformation_id": TRANSFORMATION,
             "port_direction": direction, "role": "state"}
            for name, direction in (("before", "input"), ("after", "output"))
        ],
        "constraint_logic": "classical-boolean-equations-v1",
        "equations": [
            {"id": "eq:before", "target": "before", "operator": "false", "arguments": []},
            {"id": "eq:after", "target": "after", "operator": "not", "arguments": ["before"]},
        ],
        "temporal_relations": [
            {"id": "time:backward", "source": "before", "target": "after",
             "clock_id": "declared-counter", "unit": "tick", "offset": -1,
             "meaning": "backward_time"},
        ],
        "paradox_candidates": [],
    })
    return graph, contract


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="export to a wholly absent directory")
    args = parser.parse_args()
    graph, contract = build_example()
    report = analyze_graph_topology(graph, contract).to_dict()
    if args.output_dir is not None:
        documents = {
            "receipt.json": {"schema_version": "VSTD-DATA-0.1", "hypergraph": graph.to_dict()},
            "contract.json": contract.to_dict(),
        }
        try:
            args.output_dir.mkdir(parents=True, exist_ok=False)
            for name, payload in DECLARATIONS.items():
                with (args.output_dir / f"{name}.txt").open("xb") as stream:
                    stream.write(payload)
            for name, document in documents.items():
                with (args.output_dir / name).open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            parser.exit(2, f"Export refused or incomplete; existing files are not overwritten: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
