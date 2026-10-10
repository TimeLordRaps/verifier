"""Unavailable native checkers preserve UNKNOWN across local consumers.

directed acyclic graph (DAG); command-line interface (CLI); JavaScript Object
Notation (JSON). Input/output availability is separate from a demonstrated refutation.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import composition_digest
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.runtime import polish
from verifier.runtime.public_cli import main
from test_certificate_dag_native_subjects import _fixture, _selected


def unavailable(monkeypatch: pytest.MonkeyPatch, coordinate: str,
                exception: type[Exception]) -> None:
    key = ("verifier-current-object-obligations-1", coordinate)
    route = routes._ROUTES[key]

    def missing(*args: Any, **kwargs: Any) -> dict:
        raise exception("test native checker unavailable")

    monkeypatch.setitem(routes._ROUTES, key, replace(route, replay=missing))


@pytest.mark.parametrize("exception", [OSError, ImportError])
def test_route_preserves_typed_unavailability(monkeypatch: pytest.MonkeyPatch,
                                             exception: type[Exception]) -> None:
    item, coordinate, raw, request, policy = _selected("verifier")
    unavailable(monkeypatch, coordinate, exception)
    with pytest.raises(routes.CurrentObjectRouteRefusal) as captured:
        routes.replay_current_object_certificate(raw,
            semantic_version="verifier-current-object-obligations-1", objective=coordinate,
            represented_kind=item.kind.value, expected_request=request, policy=policy)
    assert type(captured.value).__name__ == "CurrentObjectRouteUnavailable"


@pytest.mark.parametrize("exception", [OSError, ImportError])
def test_native_unavailability_is_unknown_in_dag(monkeypatch: pytest.MonkeyPatch,
                                                exception: type[Exception]) -> None:
    bundle, policy, files = _fixture("verifier")
    unavailable(monkeypatch, "VERIFIER-2.1", exception)
    result = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert result["status"] == "UNKNOWN"
    assert result["nodes"][0]["direct_status"] == "UNKNOWN"
    assert result["nodes"][0]["qualified_status"] == "UNKNOWN"
    assert result["nodes"][0]["reason"] == "CHECKER_UNAVAILABLE"


@pytest.mark.parametrize("exception", [OSError, ImportError])
def test_native_unavailability_is_unknown_in_polish(monkeypatch: pytest.MonkeyPatch,
                                                   exception: type[Exception]) -> None:
    item, coordinate, raw, request, policy = _selected("verifier")
    from verifier.runtime.artifact_snapshot import digest
    selection = {"coordinate": coordinate, "semantic_version": "verifier-current-object-obligations-1",
        "certificate_digest": digest(raw), "request": request, "policy": policy}
    unavailable(monkeypatch, coordinate, exception)
    result = polish._objective(selection, item, {digest(raw): raw}, composition_digest([item]))
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "CHECKER_UNAVAILABLE"


@pytest.mark.parametrize("exception", [OSError, ImportError])
def test_native_unavailability_is_unknown_in_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                exception: type[Exception]) -> None:
    from copy import deepcopy
    from verifier.domains.contracts import object_facets
    from verifier.core.namespace import NamespaceObject
    from verifier.runtime.gates import DEFAULT_POLICY, run_gates
    from test_cli_clearance_workflow import prepared, gate_rows
    item = NamespaceObject.create("root", "OBJECT", {"value": 3})
    policy = object_facets.object_facets_policy(trust_roots=("external-test-selector",))
    request = object_facets.object_facets_request(item, policy=policy)
    raw = object_facets.build_object_facets_certificate(request,
        canonical_bytes(item.to_dict()), policy=policy)
    target = tmp_path / "certificate.json"
    target.write_bytes(raw)
    report = prepared(target)
    identity = "current-object:" + object_facets.SEMANTIC_VERSION + ":OBJECT-1.1"
    selected = deepcopy(DEFAULT_POLICY)
    selected["selections"] = [{"gate_id": identity, "path": "artifact.json", "request": request,
        "policy": policy, "represented_kind": "OBJECT", "contract_version": "1"}]
    unavailable(monkeypatch, "OBJECT-1.1", exception)
    result = run_gates(target, polish_report_bytes=report, policy_bytes=canonical_bytes(selected))
    assert gate_rows(result)[identity]["status"] == "UNKNOWN"
    assert gate_rows(result)[identity]["results"][0]["reason"] == "CHECKER_OR_DEPENDENCY_UNAVAILABLE"


@pytest.mark.parametrize("exception", [OSError, ImportError])
def test_native_unavailability_is_unknown_at_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str],
                                               monkeypatch: pytest.MonkeyPatch,
                                               exception: type[Exception]) -> None:
    item, coordinate, raw, request, policy = _selected("verifier")
    certificate_path, request_path, policy_path = (tmp_path / name for name in
                                                  ("certificate.json", "request.json", "policy.json"))
    certificate_path.write_bytes(raw)
    request_path.write_bytes(canonical_bytes(request))
    policy_path.write_bytes(canonical_bytes(policy))
    unavailable(monkeypatch, coordinate, exception)
    exit_code = main(["current-object", "check", str(certificate_path), "--semantic-version",
        "verifier-current-object-obligations-1", "--objective", coordinate,
        "--represented-kind", item.kind.value, "--request", str(request_path),
        "--policy", str(policy_path), "--json"])
    result = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert result["computational_status"] == "UNKNOWN"
    assert result["replay_status"] == "UNAVAILABLE"


def test_semantic_refusal_remains_fail_in_dag(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = _fixture("verifier")
    unavailable(monkeypatch, "VERIFIER-2.1", ValueError)
    result = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert result["status"] == "FAIL"
    assert result["nodes"][0]["direct_status"] == "FAIL"
    assert result["nodes"][0]["reason"] == "NATIVE_REPLAY_REJECTED"


@pytest.mark.parametrize("known_failure", [False, True])
def test_unavailable_prerequisite_propagates_without_erasing_known_failure(
        monkeypatch: pytest.MonkeyPatch, known_failure: bool) -> None:
    from copy import deepcopy
    from verifier.core.namespace import NamespaceObject
    from verifier.domains.contracts import object_facets
    from verifier.runtime.artifact_snapshot import digest
    objects = [NamespaceObject.create("blocked", "OBJECT", {}),
               NamespaceObject.create("sibling", "OBJECT", {}),
               NamespaceObject.create("root", "HYPER", {}, {"support": ["blocked", "sibling"]})]
    route = next(r for r in routes.current_object_route_catalog() if r["objective"] == "OBJECT-1.1")

    def obligation(dependencies: list[dict]) -> dict:
        return {"claim_id": "representation", "semantic_version": route["semantic_version"],
            "objective": "OBJECT-1.1", "proposition_digest": route["proposition_digest"],
            "scope": route["scope"], "assumptions": [], "dependencies": dependencies}

    leaf_profile = {"schema_version": dag.PROFILE, "profile_id": "test-leaf", "profile_version": "1",
                    "object_kind": "OBJECT", "obligations": [obligation([])]}
    leaf_pin = digest(canonical_bytes(leaf_profile))
    root_profile = {"schema_version": dag.PROFILE, "profile_id": "test-root", "profile_version": "1",
        "object_kind": "HYPER", "obligations": [obligation([{"claim_id": "representation",
            "operand_role": "support", "object_kind": "OBJECT", "profile_digest": leaf_pin}])]}
    root_pin = digest(canonical_bytes(root_profile))
    files, nodes = {}, []
    for item in objects:
        policy = object_facets.object_facets_policy(trust_roots=["test:finite-prerequisite-selection"])
        request = object_facets.object_facets_request(item, policy=policy)
        raw = object_facets.build_object_facets_certificate(request,
            canonical_bytes(item.to_dict()), policy=policy)
        path = item.object_id + ".json"
        files[path] = raw
        nodes.append({"node_id": item.object_id, "object_id": item.object_id,
            "claim_id": "representation", "certificate_path": path, "certificate_digest": digest(raw),
            "request": request, "checker_policy": policy, "contract_version": "1",
            "artifact_bindings": [{"path": path, "digest": digest(raw)}],
            "facet_bindings": {"payload_digest": digest(item.payload_bytes),
                "operands_digest": digest(canonical_bytes(item.to_dict()["operands"]))}})
    bundle = {"schema_version": dag.BUNDLE, "profiles": [leaf_profile, root_profile],
        "objects": [item.to_dict() for item in objects], "nodes": nodes,
        "edges": [{"node_id": "root", "prerequisite_id": name, "operand_role": "support"}
                  for name in ("blocked", "sibling")]}
    policy = {"schema_version": dag.POLICY, "approved_profiles": [leaf_pin, root_pin],
        "required_objects": [{"object_id": item.object_id, "object_kind": item.kind.value,
            "record_digest": item.digest, "profile_digest": root_pin if item.object_id == "root" else leaf_pin}
            for item in objects], "required_roots": ["root"], "nodes": deepcopy(nodes),
        "artifact_files_digest": dag.artifact_files_digest(files)}
    key = (route["semantic_version"], "OBJECT-1.1")
    original = routes._ROUTES[key]

    def callback(raw: bytes, *, expected_request: dict, policy: dict) -> dict:
        if expected_request["object_id"] == "blocked":
            raise OSError("test unavailable prerequisite")
        if expected_request["object_id"] == "sibling" and known_failure:
            raise ValueError("test demonstrated semantic refusal")
        return original.replay(raw, expected_request=expected_request, policy=policy)

    monkeypatch.setitem(routes._ROUTES, key, replace(original, replay=callback))
    result = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    observed = {row["node_id"]: row for row in result["nodes"]}
    assert observed["blocked"]["direct_status"] == "UNKNOWN"
    assert observed["root"]["direct_status"] == "PASS"
    assert observed["sibling"]["direct_status"] == ("FAIL" if known_failure else "PASS")
    assert observed["root"]["qualified_status"] == ("FAIL" if known_failure else "UNKNOWN")
    assert result["status"] == ("FAIL" if known_failure else "UNKNOWN")
