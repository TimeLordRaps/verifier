"""Independent finite GRAPH-3.1 statics counterexamples.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node and edge counts are dimensionless.
The current-object coordinate does not inherit the historical GRAPH-3 profile.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_statics


def selected_case(edges: list[dict[str, str]], *, nodes: list[str] | None = None,
                  evidence_edges: list[dict[str, str]] | None = None,
                  **limits: int) -> tuple[dict, dict, bytes]:
    selected_nodes = ["a", "b"] if nodes is None else nodes
    retained_edges = edges if evidence_edges is None else evidence_edges
    members = [NamespaceObject.create(name, "ENV", {"fixture": name})
               for name in ["a", "b"]]
    graph = NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": digest(selected_nodes), "edges_digest": digest(edges),
    }, {"members": ["a", "b"]})
    objects = [*members, graph]
    evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": selected_nodes, "edges": retained_edges},
    })
    policy = graph_statics.graph_statics_policy(trust_roots=["externally-selected-graph"])
    request = graph_statics.graph_statics_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(selected_nodes), edges_digest=digest(edges),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None,
    )
    return request, policy, evidence


def status(request: dict, policy: dict, evidence: bytes | None) -> str:
    cert = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    replay = graph_statics.recheck_graph_statics_certificate(
        cert, expected_request=request, policy=policy)
    assert replay["coordinate"] == "GRAPH-3.1"
    assert replay["object_profile_conformance"] == "NOT_ESTABLISHED"
    return replay["status"]


def test_selected_acyclic_edges_pass_with_bounded_meaning() -> None:
    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    assert status(request, policy, evidence) == "PASS"


def test_default_bounds_cover_large_repository_graphs_without_becoming_unbounded() -> None:
    request, _, _ = selected_case([])
    assert request["limits"]["max_objects"] == 4096
    assert request["limits"]["max_nodes"] == 4096
    assert request["limits"]["max_edges"] == 16384
    assert request["limits"]["max_items"] == 65536
    assert all(type(value) is int and 0 < value <= 4 * 1024 * 1024
               for value in request["limits"].values())


@pytest.mark.parametrize("edges", [
    [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}],
    [{"source": "a", "target": "a"}],
    [{"source": "a", "target": "c"}],
    [{"source": "a", "target": "b"}, {"source": "a", "target": "b"}],
])
def test_cycle_self_edge_dangling_and_duplicate_refute(edges: list[dict[str, str]]) -> None:
    request, policy, evidence = selected_case(edges)
    assert status(request, policy, evidence) == "FAIL"


def test_retained_edge_omission_cannot_get_wrong_reason_pass() -> None:
    selected = [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}]
    request, policy, evidence = selected_case(selected,
        evidence_edges=[{"source": "a", "target": "b"}])
    assert status(request, policy, evidence) == "FAIL"


def test_selected_nodes_must_equal_declared_graph_members() -> None:
    request, policy, evidence = selected_case([], nodes=["a"])
    assert status(request, policy, evidence) == "FAIL"


def test_missing_evidence_and_exhausted_bound_remain_unknown() -> None:
    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    assert status(request, policy, None) == "UNKNOWN"
    request, policy, evidence = selected_case([{"source": "a", "target": "b"}], max_items=1)
    assert status(request, policy, evidence) == "UNKNOWN"


def test_external_edge_selection_cannot_be_substituted_on_replay() -> None:
    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    cert = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    wrong = {**request, "edges_digest": "sha256:" + "0" * 64}
    with pytest.raises(graph_statics.GraphStaticsError):
        graph_statics.recheck_graph_statics_certificate(
            cert, expected_request=wrong, policy=policy)


def test_public_route_and_inventory_register_only_bounded_graph_statics() -> None:
    from verifier.domains.contracts.current_object_routes import (
        current_object_route_catalog, replay_current_object_certificate)
    from verifier.domains.inventory import get_slot

    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    cert = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    replay = replay_current_object_certificate(cert,
        semantic_version=graph_statics.SEMANTIC_VERSION,
        objective="GRAPH-3.1", represented_kind="GRAPH",
        expected_request=request, policy=policy)
    assert replay["computational_status"] == "PASS"
    assert replay["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    route = next(row for row in current_object_route_catalog()
                 if row["objective"] == "GRAPH-3.1")
    assert route["represented_kind_rule"] == "GRAPH"
    slot = get_slot("GRAPH", 3).to_dict()
    assert slot["status"] == "REPLAYABLE"
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert {item["coordinate"] for item in slot["registered_objectives"]} == {"GRAPH-3.1"}


def test_public_command_replays_selected_graph_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    for name, data in (
        ("request", canonical_bytes(request)),
        ("policy", canonical_bytes(policy)),
        ("certificate", graph_statics.build_graph_statics_certificate(
            request, evidence, policy=policy)),
    ):
        (tmp_path / f"{name}.json").write_bytes(data)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", graph_statics.SEMANTIC_VERSION,
        "--objective", "GRAPH-3.1", "--represented-kind", "GRAPH",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("relative", [
    "domains/contracts/graph_statics.py", "standard/CURRENT_GRAPH_STATICS.md",
])
def test_graph_dependency_change_invalidates_polish_digest(
    relative: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged GRAPH statics dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before


def test_installed_wheel_replays_graph_statics_without_source_tree(tmp_path: Path, wheel_source: Path) -> None:
    root = wheel_source
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
        "--no-cache-dir", "-w", str(wheel_dir), str(root)],
        check=True, timeout=60)
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    target = tmp_path / "site-packages"
    target.mkdir()
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "verifier/domains/contracts/graph_statics.py" in names
        assert "verifier/standard/CURRENT_GRAPH_STATICS.md" in names
        archive.extractall(target)

    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    cert = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    work = tmp_path / "isolated"
    work.mkdir()
    (work / "certificate.json").write_bytes(cert)
    (work / "request.json").write_bytes(canonical_bytes(request))
    (work / "policy.json").write_bytes(canonical_bytes(policy))
    env = {"PYTHONPATH": str(target), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
           "PATH": os.environ.get("PATH", "")}
    command = ("import sys; from verifier.runtime.public_cli import main; "
        "sys.exit(main(['current-object', 'check', 'certificate.json', "
        "'--semantic-version', 'verifier-current-object-obligations-1', "
        "'--objective', 'GRAPH-3.1', '--represented-kind', 'GRAPH', "
        "'--request', 'request.json', '--policy', 'policy.json', '--json']))")
    run = subprocess.run([sys.executable, "-S", "-c", command], cwd=work,
        env=env, capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(run.stdout)["computational_status"] == "PASS"


def test_graph_certificate_cannot_emit_redacted_replay_evidence() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import (
        DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty)

    request, policy, evidence = selected_case([{"source": "a", "target": "b"}])
    value = json.loads(graph_statics.build_graph_statics_certificate(
        request, evidence, policy=policy))
    surface = DisclosureSurface("GRAPH",
        tuple(field for field in value if field != "evidence_payloads"),
        ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",))
                   for field in surface.disclosed_fields)
    context = EmissionContext(
        ObserverParty("reader", "reviewer", "local-evaluation"),
        "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)
