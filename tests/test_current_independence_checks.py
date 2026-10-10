"""Adverse controls for finite retained provenance separation.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Simulation (SIM).
Different retained sources do not establish real-world independent witnesses.
"""
from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from test_current_typed_facets import collection

KINDS = "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT BOT TOKEN".split()


def contract() -> Any:
    return importlib.import_module("verifier.domains.contracts.independence_checks")


def facets(objects: list[NamespaceObject], kind: str) -> dict[str, Any]:
    """Fixture inventory derived without importing the checker binder."""
    by_id = {obj.object_id: obj for obj in objects}
    subject = by_id[kind.lower()]
    result = {"subject_record": subject.digest, "payload": digest(subject.payload), "operands": {}, "dependencies": {}}
    pending = []
    for role, refs in subject.operands:
        result["operands"][role] = {}
        for ref in refs:
            result["operands"][role][ref] = by_id[ref].digest
            pending.append(ref)
    seen = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        result["dependencies"][ref] = by_id[ref].digest
        pending.extend(target for _, refs in by_id[ref].operands for target in refs)
    return result


def inputs(kind: str, objects: list[NamespaceObject] | None = None,
           dimensions: list[str] | None = None, **limits: int) -> tuple[Any, dict, dict, dict]:
    c = contract()
    objects = collection() if objects is None else objects
    subject = next(obj for obj in objects if obj.object_id == kind.lower())
    cd = composition_digest(objects)
    artifacts = {}
    def retain(data: bytes) -> str:
        ref = "sha256:" + __import__("hashlib").sha256(data).hexdigest()
        artifacts[ref] = base64.b64encode(data).decode("ascii")
        return ref
    sources = {}
    for role in ("producer", "checker"):
        support = retain(("Retained " + role + " implementation artifact\n").encode())
        trace = retain(canonical_bytes({"schema_version": c.TRACE_VERSION, "role": role,
            "object_kind": kind, "subject_id": subject.object_id, "object_digest": subject.digest,
            "collection_digest": cd, "facets": facets(objects, kind)}))
        sources[role + "-support"] = {"artifact_ref": support, "parents": []}
        sources[role] = {"artifact_ref": trace, "parents": [role + "-support"]}
    evidence = {"schema_version": c.EVIDENCE_VERSION,
        "collection": {"schema_version": c.COLLECTION_VERSION,
            "objects": [obj.to_dict() for obj in sorted(objects, key=lambda obj: obj.object_id)]},
        "sources": sources, "artifacts": artifacts}
    policy = c.independence_checks_policy(trust_roots=["selected-finite-documentary-source-model"],
        source_roots={"producer": ["producer"], "checker": ["checker"]},
        graph_digest=digest(sources), required_dimensions=dimensions or ["retained_provenance"])
    request = c.independence_checks_request(object_kind=kind, subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=cd, evidence_ref=digest(evidence),
        policy=policy, limits=limits or None)
    return c, request, policy, evidence


def reselect(c: Any, request: dict, policy: dict, evidence: dict) -> None:
    policy["graph_digest"] = digest(evidence["sources"])
    request["policy_digest"] = digest(policy)
    request["evidence_ref"] = digest(evidence)


def replay(c: Any, request: dict, policy: dict, evidence: dict | None) -> dict:
    cert = c.build_independence_checks_certificate(request,
        None if evidence is None else canonical_bytes(evidence), policy=policy)
    return c.recheck_independence_checks_certificate(cert, expected_request=request, policy=policy)


def mutate_trace(evidence: dict, source_role: str, **changes: Any) -> None:
    source = evidence["sources"][source_role]
    trace = json.loads(base64.b64decode(evidence["artifacts"][source["artifact_ref"]]))
    trace.update(changes)
    data = canonical_bytes(trace)
    ref = digest(trace)
    evidence["artifacts"].pop(source["artifact_ref"])
    evidence["artifacts"][ref] = base64.b64encode(data).decode("ascii")
    source["artifact_ref"] = ref


def test_family_capability_exists_without_promoting_sim_primary() -> None:
    c = contract()
    assert set(c.KIND_SCOPES) == set(KINDS)
    assert len({c.IndependenceChecksDescriptor(kind).PROPOSITION_DIGEST for kind in KINDS}) == 25
    with pytest.raises(c.IndependenceChecksError):
        c.coordinate("SIM")


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_replays_exact_artifacts_and_selected_source_footprints(kind: str) -> None:
    c, request, policy, evidence = inputs(kind)
    result = replay(c, request, policy, evidence)
    assert result["status"] == "PASS" and result["object_kind"] == kind
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["independence_tier_conformance"] == "NOT_ESTABLISHED"
    assert result["dimensions"]["retained_provenance"] == "PASS"
    assert all(result["dimensions"][name] == "UNKNOWN" for name in
        ("actor_identity", "authority", "implementation", "runtime", "common_cause", "causal", "statistical"))
    assert result["source_authenticity"] == "UNKNOWN"


@pytest.mark.parametrize("kind", KINDS)
def test_same_recorded_dependency_refutes_different_claimed_source_names(kind: str) -> None:
    c, request, policy, evidence = inputs(kind)
    evidence["sources"]["checker"]["parents"] = ["producer-support"]
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_requires_complete_exact_facet_and_operand_trace(kind: str) -> None:
    c, request, policy, evidence = inputs(kind)
    expected = facets(collection(), kind)
    if expected["operands"]:
        expected["operands"].pop(next(iter(expected["operands"])))
    else:
        expected.pop("payload")
    mutate_trace(evidence, "checker", facets=expected)
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_preserves_unknown_for_unretained_source_artifact(kind: str) -> None:
    c, request, policy, evidence = inputs(kind)
    evidence["artifacts"].pop(evidence["sources"]["checker-support"]["artifact_ref"])
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_refutes_its_own_malformed_operand_contract(kind: str) -> None:
    objects = collection()
    selected = next(obj for obj in objects if obj.object_id == kind.lower())
    operands = {} if kind == "HYPER" else {**selected.to_dict()["operands"], "undeclared": ["object"]}
    broken = NamespaceObject.create(selected.object_id, kind, selected.payload, operands)
    c, request, policy, evidence = inputs(kind, [broken if obj == selected else obj for obj in objects])
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("dimension", ["actor_identity", "authority", "implementation", "runtime", "common_cause", "causal", "statistical"])
def test_additional_independence_dimensions_cannot_be_inferred(dimension: str) -> None:
    c, request, policy, evidence = inputs("MODEL", dimensions=["retained_provenance", dimension])
    assert replay(c, request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["missing", "objects", "operations", "nodes", "edges", "bytes", "composition"])
def test_selected_budgets_and_missing_evidence_remain_unknown(case: str) -> None:
    limits = {"max_objects": 1} if case == "objects" else {"max_operations": 1} if case == "operations" else \
        {"max_source_nodes": 1} if case == "nodes" else {"max_source_edges": 1} if case == "edges" else \
        {"max_evidence_bytes": 1} if case == "bytes" else {"max_composition_operations": 1} if case == "composition" else {}
    c, request, policy, evidence = inputs("MODEL", **limits)
    assert replay(c, request, policy, None if case == "missing" else evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["root", "parent", "artifact", "support"])
def test_missing_documentary_coverage_never_becomes_a_pass(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    if case == "root":
        policy["source_roots"]["checker"] = ["absent"]
    elif case == "parent":
        evidence["sources"]["checker"]["parents"] = ["absent"]
    elif case == "artifact":
        evidence["artifacts"].pop(evidence["sources"]["checker"]["artifact_ref"])
    else:
        evidence["sources"]["checker"]["parents"] = []
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["cycle", "alias-artifact", "overlap-root", "false-bytes", "false-graph", "wrong-role", "wrong-kind", "wrong-subject", "wrong-collection", "false-facet", "extra-facet", "extra-artifact"])
def test_refuted_documentary_bindings_and_known_common_dependencies_fail(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    if case == "cycle":
        evidence["sources"]["checker-support"]["parents"] = ["checker"]
    elif case == "alias-artifact":
        evidence["sources"]["checker-support"]["artifact_ref"] = evidence["sources"]["producer-support"]["artifact_ref"]
        evidence["artifacts"].pop(next(ref for ref, data in evidence["artifacts"].items()
            if base64.b64decode(data) == b"Retained checker implementation artifact\n"))
    elif case == "overlap-root":
        policy["source_roots"]["checker"] = ["producer"]
    elif case == "false-bytes":
        evidence["artifacts"][evidence["sources"]["checker-support"]["artifact_ref"]] = base64.b64encode(b"tampered").decode()
    elif case == "wrong-role":
        mutate_trace(evidence, "checker", role="producer")
    elif case in ("wrong-kind", "wrong-subject", "wrong-collection"):
        key, value = {"wrong-kind": ("object_kind", "TRAIN"), "wrong-subject": ("subject_id", "train"),
            "wrong-collection": ("collection_digest", "sha256:" + "0" * 64)}[case]
        mutate_trace(evidence, "checker", **{key: value})
    elif case in ("false-facet", "extra-facet"):
        inventory = facets(collection(), "MODEL")
        inventory["payload" if case == "false-facet" else "extra"] = "sha256:" + "0" * 64
        mutate_trace(evidence, "checker", facets=inventory)
    elif case == "extra-artifact":
        evidence["artifacts"]["sha256:" + "0" * 64] = base64.b64encode(b"unbound").decode()
    reselect(c, request, policy, evidence)
    if case == "false-graph":
        policy["graph_digest"] = "sha256:" + "0" * 64
        request["policy_digest"] = digest(policy)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["kind", "subject", "record", "collection", "policy", "carried-result", "carried-evidence"])
def test_rehashed_certificate_and_external_selection_substitution_are_rejected(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    cert = c.build_independence_checks_certificate(request, canonical_bytes(evidence), policy=policy)
    if case.startswith("carried"):
        value = json.loads(cert)
        if case == "carried-result":
            value["result"]["dimensions"]["actor_identity"] = "PASS"
        else:
            value["evidence_payloads"] = {}
        value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
        cert = canonical_bytes(value)
    elif case == "policy":
        policy["required_dimensions"].append("causal")
    else:
        key, value = {"kind": ("object_kind", "TRAIN"), "subject": ("subject_id", "train"),
            "record": ("object_digest", "sha256:" + "0" * 64), "collection": ("collection_digest", "sha256:" + "0" * 64)}[case]
        request[key] = value
    with pytest.raises(c.IndependenceChecksError):
        c.recheck_independence_checks_certificate(cert, expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_public_routing_integration_fixture_replays_kind_and_preserves_sim(kind: str, monkeypatch: Any) -> None:
    from verifier.domains.contracts import current_object_routes as routes
    c, request, policy, evidence = inputs(kind)
    sim_route = routes.select_current_object_route(semantic_version=c.SEMANTIC_VERSION,
        objective="SIM-5.1", represented_kind="SIM")
    descriptor = c.IndependenceChecksDescriptor(kind)
    monkeypatch.setitem(routes._ROUTES, (c.SEMANTIC_VERSION, c.coordinate(kind)),
        routes._Route(descriptor, c.recheck_independence_checks_certificate, kind, c.KIND_SCOPES[kind]))
    cert = c.build_independence_checks_certificate(request, canonical_bytes(evidence), policy=policy)
    result = routes.replay_current_object_certificate(cert, semantic_version=c.SEMANTIC_VERSION,
        objective=c.coordinate(kind), represented_kind=kind, expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["dimensions"]["causal"] == "UNKNOWN"
    row = next(row for row in routes.current_object_route_catalog() if row["objective"] == c.coordinate(kind))
    assert row["proposition_digest"] == descriptor.PROPOSITION_DIGEST
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(cert, semantic_version=c.SEMANTIC_VERSION,
            objective=c.coordinate(kind), represented_kind="SIM", expected_request=request, policy=policy)
    assert routes.select_current_object_route(semantic_version=c.SEMANTIC_VERSION,
        objective="SIM-5.1", represented_kind="SIM") is sim_route


@pytest.mark.parametrize("relative", ["domains/contracts/independence_checks.py", "domains/contracts/typed_facets.py",
    "domains/contracts/retained_selection.py", "standard/CURRENT_INDEPENDENCE_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_direct_and_selected_dependency_changes_invalidate_mechanism(relative: str, monkeypatch: Any) -> None:
    c = contract()
    original = Path.read_bytes
    target = Path(c.__file__).parents[2] / relative
    before = c.mechanism_digest()
    def substituted(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", substituted)
    assert c.mechanism_digest() != before


def test_transitive_operand_evidence_cannot_be_omitted_while_direct_operands_match() -> None:
    c, request, policy, evidence = inputs("AGENT")
    inventory = facets(collection(), "AGENT")
    assert "data" in inventory["dependencies"] and "data" not in inventory["operands"]["model"]
    inventory["dependencies"].pop("data")
    mutate_trace(evidence, "checker", facets=inventory)
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


def test_arbitrary_hyper_roles_and_identifiers_use_unambiguous_nested_bindings() -> None:
    objects = collection()
    objects += [NamespaceObject.create("b:c", "OBJECT", {"tag": "first"}),
        NamespaceObject.create("c", "OBJECT", {"tag": "second"})]
    original = next(obj for obj in objects if obj.object_id == "hyper")
    changed = NamespaceObject.create("hyper", "HYPER", original.payload, {"a": ["b:c"], "a:b": ["c"]})
    objects = [changed if obj == original else obj for obj in objects]
    c, request, policy, evidence = inputs("HYPER", objects)
    assert replay(c, request, policy, evidence)["status"] == "PASS"
    inventory = facets(objects, "HYPER")
    inventory["operands"]["a"]["b:c"] = inventory["operands"]["a:b"]["c"]
    mutate_trace(evidence, "checker", facets=inventory)
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["overlap", "false-trace"])
def test_decidable_refutation_survives_missing_artifacts_and_unknown_actor_dimension(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL", dimensions=["retained_provenance", "actor_identity"])
    evidence["artifacts"].pop(evidence["sources"]["producer-support"]["artifact_ref"])
    if case == "overlap":
        evidence["sources"]["checker"]["parents"] = ["producer-support"]
    else:
        mutate_trace(evidence, "checker", subject_id="train")
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


def test_source_graph_traversal_covers_shared_transitive_dependencies() -> None:
    c, request, policy, evidence = inputs("MODEL")
    ref = evidence["sources"]["producer-support"]["artifact_ref"]
    evidence["sources"]["shared-transitive"] = {"artifact_ref": ref, "parents": []}
    evidence["sources"]["producer-support"]["parents"] = ["shared-transitive"]
    evidence["sources"]["checker-support"]["parents"] = ["shared-transitive"]
    reselect(c, request, policy, evidence)
    result = replay(c, request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "share a recorded source node" in result["evaluation"]["details"]


@pytest.mark.parametrize("case", ["blank-root", "duplicate-root", "empty-roots", "empty-dimensions", "unknown-dimension", "boolean-budget", "mechanism", "active-subclass"])
def test_unsupported_policy_and_active_selection_values_are_rejected(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    if case == "blank-root":
        policy["source_roots"]["checker"] = [" "]
    elif case == "duplicate-root":
        policy["source_roots"]["checker"] = ["checker", "checker"]
    elif case == "empty-roots":
        policy["source_roots"]["checker"] = []
    elif case == "empty-dimensions":
        policy["required_dimensions"] = []
    elif case == "unknown-dimension":
        policy["required_dimensions"].append("claimed_names")
    elif case == "boolean-budget":
        request["limits"]["max_objects"] = True
    elif case == "mechanism":
        policy["mechanism_digest"] = "sha256:" + "0" * 64
    else:
        class ActiveText(str):
            def __eq__(self, other: Any) -> bool:
                raise AssertionError("active equality must not execute")
        policy["source_roots"]["checker"] = [ActiveText("checker")]
    with pytest.raises(c.IndependenceChecksError):
        replay(c, request, policy, evidence)


def test_routing_fixture_preserves_unknown_fail_and_rejected_boundaries(monkeypatch: Any) -> None:
    from verifier.domains.contracts import current_object_routes as routes
    c, request, policy, evidence = inputs("MODEL")
    monkeypatch.setitem(routes._ROUTES, (c.SEMANTIC_VERSION, c.coordinate("MODEL")),
        routes._Route(c.IndependenceChecksDescriptor("MODEL"), c.recheck_independence_checks_certificate, "MODEL", c.SCOPE))
    def route(cert: bytes) -> dict:
        return routes.replay_current_object_certificate(cert, semantic_version=c.SEMANTIC_VERSION,
            objective=c.coordinate("MODEL"), represented_kind="MODEL", expected_request=request, policy=policy)
    cert = c.build_independence_checks_certificate(request, None, policy=policy)
    assert route(cert)["computational_status"] == "UNKNOWN"
    evidence["sources"]["checker"]["parents"] = ["producer-support"]
    reselect(c, request, policy, evidence)
    cert = c.build_independence_checks_certificate(request, canonical_bytes(evidence), policy=policy)
    assert route(cert)["computational_status"] == "FAIL"
    value = json.loads(cert)
    value["result"]["status"] = "PASS"
    value["digest"] = digest({key: child for key, child in value.items() if key != "digest"})
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        route(canonical_bytes(value))


@pytest.mark.parametrize("case", ["deep", "numeric", "selected-depth", "selected-numeric"])
def test_evidence_parser_capacity_exhaustion_is_unknown(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    if case == "deep":
        data = b'[' * 2000 + b'0' + b']' * 2000
    elif case == "numeric":
        data = b'{"oversized_integer":' + b'1' * 5000 + b'}'
    else:
        data = canonical_bytes(evidence)
        request["limits"]["max_json_depth" if case == "selected-depth" else "max_numeric_token_bytes"] = 1
        if case == "selected-numeric":
            value = json.loads(data)
            value["collection"]["objects"][0]["payload"]["numeric"] = 12345
            data = canonical_bytes(value)
    request["evidence_ref"] = "sha256:" + __import__("hashlib").sha256(data).hexdigest()
    cert = c.build_independence_checks_certificate(request, data, policy=policy)
    result = c.recheck_independence_checks_certificate(cert, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert "bound exhausted" in result["evaluation"]["details"]


@pytest.mark.parametrize("data", [b'{"schema_version":1,"schema_version":2}', b'{"n":NaN}', b'{', b'\xff'])
def test_malformed_evidence_within_parser_capacity_is_fail(data: bytes) -> None:
    c, request, policy, evidence = inputs("MODEL")
    request["evidence_ref"] = "sha256:" + __import__("hashlib").sha256(data).hexdigest()
    cert = c.build_independence_checks_certificate(request, data, policy=policy)
    assert c.recheck_independence_checks_certificate(cert, expected_request=request, policy=policy)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["subject", "record", "collection", "cross-kind"])
def test_isolated_external_subject_and_domain_substitution_is_refuted(case: str) -> None:
    c, request, policy, evidence = inputs("MODEL")
    if case == "subject":
        request["subject_id"] = "train"
    elif case == "record":
        request["object_digest"] = next(obj.digest for obj in collection() if obj.object_id == "train")
    elif case == "collection":
        request["collection_digest"] = "sha256:" + "0" * 64
    else:
        request["object_kind"] = "TRAIN"
        request["coordinate"] = c.coordinate("TRAIN")
        request["proposition_digest"] = c.IndependenceChecksDescriptor("TRAIN").PROPOSITION_DIGEST
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


def test_graph_member_type_rebinding_cannot_pass_by_reselecting_every_commitment() -> None:
    objects = collection()
    original = next(obj for obj in objects if obj.object_id == "graph")
    malformed = NamespaceObject.create("graph", "GRAPH", {"element_kind": "ENV"}, {"members": ["data"]})
    c, request, policy, evidence = inputs("GRAPH", [malformed if obj == original else obj for obj in objects])
    assert replay(c, request, policy, evidence)["status"] == "FAIL"


def test_selected_exact_record_substitution_changes_its_source_trace_binding() -> None:
    c, request, policy, evidence = inputs("GRAPH")
    objects = collection()
    original = next(obj for obj in objects if obj.object_id == "graph")
    changed = NamespaceObject.create("graph", "GRAPH", {**original.payload, "edges": [["a", "b"]]}, original.to_dict()["operands"])
    objects = [changed if obj == original else obj for obj in objects]
    evidence["collection"]["objects"] = [obj.to_dict() for obj in sorted(objects, key=lambda obj: obj.object_id)]
    request["object_digest"] = changed.digest
    request["collection_digest"] = composition_digest(objects)
    reselect(c, request, policy, evidence)
    assert replay(c, request, policy, evidence)["status"] == "FAIL"
