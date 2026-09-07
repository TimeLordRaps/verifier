"""Verifier Standard (VSTD) topology command, schema and planning boundaries.

JavaScript Object Notation (JSON) documents here describe noncritical Boolean
switches and declared clock coordinates, not an observed physical experiment.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator

from verifier.data.models import (
    ArtifactNode, ArtifactType, HyperedgePort, ProvenanceHypergraph,
    TransformationHyperedge, TransformationType,
)
from verifier.runtime.public_cli import main


ROOT = Path(__file__).resolve().parents[1]


def _documents(tmp_path: Path, *, contradict: bool = False) -> tuple[Path, Path]:
    from verifier.interoperability.graph_topology import graph_topology_binding_digest

    graph = ProvenanceHypergraph()
    for name in ("before", "after"):
        graph.add_artifact(ArtifactNode(
            artifact_id=name, label=name, artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="0" * 64, byte_size=0, record_count=0,
            mime_type="application/octet-stream", metadata_digest="1" * 64,
            provenance_digest="2" * 64,
        ))
    graph.add_transformation(TransformationHyperedge(
        transformation_id="switch", label="declared switch relation",
        transformation_type=TransformationType.NORMALIZATION,
        inputs=(HyperedgePort("before", "state"),),
        outputs=(HyperedgePort("after", "state"),),
        software_provenance={}, parameters={}, execution_environment={},
    ))
    contract = {
        "schema_version": "VSTD-GRAPH-TOPOLOGY-EXPERIMENTAL-0.1",
        "graph_digest": graph_topology_binding_digest(graph),
        "bindings": [
            {"variable_id": name, "artifact_id": name, "transformation_id": "switch",
             "port_direction": direction, "role": "state"}
            for name, direction in (("before", "input"), ("after", "output"))
        ],
        "constraint_logic": "classical-boolean-equations-v1",
        "equations": [
            {"id": "initial", "target": "before", "operator": "false", "arguments": []},
            {"id": "toggle", "target": "after", "operator": "not", "arguments": ["before"]},
        ],
        "temporal_relations": [
            {"id": "earlier", "source": "before", "target": "after",
             "clock_id": "declared-counter", "unit": "tick", "offset": -1,
             "meaning": "backward_time"},
        ],
        "paradox_candidates": [],
    }
    if contradict:
        contract["equations"].append(
            {"id": "opposite", "target": "before", "operator": "true", "arguments": []}
        )
    contract["bindings"].sort(key=lambda item: item["variable_id"])
    receipt_path, contract_path = tmp_path / "receipt.json", tmp_path / "contract.json"
    # A graph inspection envelope, deliberately not a fully validated receipt.
    receipt_path.write_text(json.dumps({
        "schema_version": "VSTD-DATA-0.1", "hypergraph": graph.to_dict(),
    }), encoding="utf-8")
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return receipt_path, contract_path


def test_topology_command_is_discoverable(capsys) -> None:
    with pytest.raises(SystemExit) as result:
        main(["data", "--help"])
    assert result.value.code == 0
    assert "topology" in capsys.readouterr().out


@pytest.mark.parametrize("contradict,expected", [(False, 0), (True, 1)])
def test_topology_command_bound_diagnostics(tmp_path, capsys, contradict, expected) -> None:
    receipt, contract = _documents(tmp_path, contradict=contradict)
    before = (receipt.read_bytes(), contract.read_bytes())
    arguments = ["data", "topology", str(receipt), "--contract", str(contract), "--json"]
    assert main(arguments) == expected
    first = capsys.readouterr()
    assert first.err == ""
    report = json.loads(first.out)
    assert report["boolean_consistency"]["status"] == (
        "CONFLICTED" if contradict else "CONSISTENT"
    )
    assert report["temporal_consistency"]["status"] == "CONSISTENT"
    assert report["verification_effect"] == "NONE"
    assert main(arguments) == expected
    assert capsys.readouterr().out == first.out
    assert (receipt.read_bytes(), contract.read_bytes()) == before


def test_topology_command_omitted_time_semantics_remains_unestablished(tmp_path, capsys) -> None:
    receipt, contract = _documents(tmp_path)
    payload = json.loads(contract.read_text(encoding="utf-8"))
    payload["temporal_relations"] = []
    contract.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["data", "topology", str(receipt), "--contract", str(contract)]) == 2
    output = capsys.readouterr()
    assert "NOT_ESTABLISHED" in output.out
    assert "conformance" in output.out


@pytest.mark.parametrize("target", ["receipt", "contract"])
def test_topology_command_rejects_duplicate_keys(tmp_path, capsys, target) -> None:
    receipt, contract = _documents(tmp_path)
    path = receipt if target == "receipt" else contract
    content = path.read_text(encoding="utf-8")
    path.write_text('{"schema_version":"forged",' + content[1:], encoding="utf-8")
    assert main(["data", "topology", str(receipt), "--contract", str(contract), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "duplicate" in output.err.lower()


@pytest.mark.parametrize("broken", [42, [42], None])
def test_topology_command_rejects_malformed_graph_collections(tmp_path, capsys, broken) -> None:
    receipt, contract = _documents(tmp_path)
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["hypergraph"]["artifacts"] = broken
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["data", "topology", str(receipt), "--contract", str(contract), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "[FAIL]" in output.err


def test_topology_command_bounded_read(tmp_path, capsys) -> None:
    receipt, contract = _documents(tmp_path)
    contract.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    assert main(["data", "topology", str(receipt), "--contract", str(contract), "--json"]) == 1
    assert "document limit" in capsys.readouterr().err


def test_topology_document_reader_rejects_directory_before_open(tmp_path, monkeypatch) -> None:
    from verifier.runtime.graph_topology_cli import _read_document

    def forbidden(*args, **kwargs):
        raise AssertionError("nonregular inputs must not be opened")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ValueError, match="ordinary file"):
        _read_document(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipe creation requires Unix")
def test_topology_document_reader_rejects_pipe_without_waiting(tmp_path) -> None:
    from verifier.runtime.graph_topology_cli import _read_document

    pipe = tmp_path / "input.pipe"
    os.mkfifo(pipe)
    with pytest.raises(ValueError, match="ordinary file"):
        _read_document(pipe)


def test_topology_contract_schema_and_runtime_agree_on_fixture(tmp_path) -> None:
    from verifier.interoperability.graph_topology import GraphTopologyContract

    _, contract = _documents(tmp_path)
    payload = json.loads(contract.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "standard/schemas/graph-topology.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    assert GraphTopologyContract.from_dict(payload).to_dict() == payload
    payload["temporal_relations"][0]["offset"] = True
    assert list(Draft202012Validator(schema).iter_errors(payload))


def test_surface_detection_and_planning_match_topology_without_execution(tmp_path, capsys, monkeypatch) -> None:
    from verifier.interoperability import graph_topology

    def forbidden(*args, **kwargs):
        raise AssertionError("planning must not execute topology analysis")

    monkeypatch.setattr(graph_topology, "analyze_graph_topology", forbidden)
    source = ROOT / "examples/verification_geometry_residual/geometry.json"
    geometry = tmp_path / "geometry.json"
    geometry.write_text(source.read_text(encoding="utf-8").replace(
        "mechanism:fixture-test", "mechanism:graph-topology-analysis"
    ), encoding="utf-8")
    assert main(["surface", "analyze", str(geometry), "--plan", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["plan"]["execution_performed"] is False
    assert any(item["component_id"] == "component:graph-topology-analyzer"
               and item["status"] == "CANDIDATE" for item in report["plan"]["candidates"])


def test_exported_example_is_retrievable_runnable_and_non_overwriting(tmp_path, capsys) -> None:
    destination = tmp_path / "specimen"
    command = [sys.executable, "-u", str(ROOT / "examples/graph_topology/demo.py"),
               "--output-dir", str(destination)]
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    # This one-report specimen is bounded to 30 seconds; captured bytes are replayed below.
    first = subprocess.run(command, cwd=ROOT, env=environment, timeout=30,
                           check=False, text=True, capture_output=True)
    print(first.stdout)
    print(first.stderr)
    assert first.returncode == 0
    report = json.loads(first.stdout)
    assert report["boolean_consistency"]["witness"] == {"before": False, "after": True}
    assert report["verification_effect"] == "NONE"
    files = {path.name: path.read_bytes() for path in destination.iterdir()}
    assert set(files) == {"receipt.json", "contract.json", "before.txt", "after.txt"}
    envelope = json.loads(files["receipt.json"])
    for artifact in envelope["hypergraph"]["artifacts"]:
        assert artifact["content_digest"] == hashlib.sha256(files[artifact["storage_uris"][0]]).hexdigest()
        assert artifact["status"] == "UNKNOWN"
    capsys.readouterr()
    assert main(["data", "topology", str(destination), "--contract",
                 str(destination / "contract.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["boolean_consistency"] == report["boolean_consistency"]
    second = subprocess.run(command, cwd=ROOT, env=environment, timeout=30,
                            check=False, text=True, capture_output=True)
    print(second.stdout)
    print(second.stderr)
    assert second.returncode == 2
    assert "not overwritten" in second.stderr
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == files
