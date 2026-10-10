"""Verifier Standard (VSTD) finite simulation (SIM) surface accounting.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind independent synthetic fixtures. No production private key is used.
Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
Times and states have the selected model's units; counts are dimensionless.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import (sim_dynamics, sim_shard_coverage,
    sim_shard_relations, sim_shard_signatures)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


SEAL_ABSENT = ("OPTIONAL_DEPENDENCY_ABSENT: the signed shard child is Ed25519-signed and needs the seal extra (cryptography); "
               "the platform-python-contracts workflow job installs it")


def signed_child(*, row_change: str | None = None, unavailable: bool = False,
                 forged: bool = False):
    """Build a two-variable trace without the new surface-accounting checker."""
    Ed25519PrivateKey = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519", reason=SEAL_ABSENT).Ed25519PrivateKey
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization", reason=SEAL_ABSENT)

    inputs = {"states": [{"x": 0.0, "y": 2.0}, {"x": 1.0, "y": 3.0},
                         {"x": 2.0, "y": 4.0}],
              "entropy": [1.0, 1.0], "times": [0.0, 1.0, 2.0]}
    program = {name: {"op": "add", "args": [{"var": name}, {"var": "entropy"}]}
               for name in ("x", "y")}
    artifact = {"transition": program, "initial_state": inputs["states"][0],
                "trajectory_digest": digest(inputs["states"]),
                "entropy_digest": digest(inputs["entropy"]),
                "times_digest": digest(inputs["times"])}
    objects = [NamespaceObject.create("data", "DATA", {}),
               NamespaceObject.create("checker", "VERIFIER", {}),
               NamespaceObject.create("world", "OBJECT", {}),
               NamespaceObject.create("env", "ENV", {})]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-retained-trajectory-replay",
        "artifact_digest": digest(artifact), "inputs_digest": digest(inputs)},
        {"data": ["data"], "verifier": ["checker"],
         "objects": ["world"], "env": ["env"]})
    objects.append(subject)
    common = {"subject_id": "sim", "object_digest": subject.digest,
              "collection_digest": composition_digest(objects)}
    data = canonical_bytes({"schema_version": sim_dynamics.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects], "artifact": artifact,
        "inputs": inputs})
    policy = sim_dynamics.sim_dynamics_policy(trust_roots=["synthetic-trajectory"])
    request = sim_dynamics.sim_dynamics_request(**common,
        artifact_digest=digest(artifact), inputs_digest=digest(inputs),
        expected_counts={"states": 3, "transitions": 2}, evidence_ref=byte_digest(data),
        policy=policy)
    child = sim_dynamics.build_sim_dynamics_certificate(request, data, policy=policy)
    rows = {"left": [{"time": t, "state": {"l": float(i)}}
                     for i, t in enumerate(inputs["times"])],
            "right": [{"time": t, "state": {"r": float(i + 2)}}
                      for i, t in enumerate(inputs["times"])]}
    if row_change == "later-value":
        rows["left"][-1]["state"]["l"] = 9.0
        rows["right"][-1]["state"]["r"] = 11.0
    elif row_change == "representation":
        rows["left"][0]["state"]["l"] = 0
    elif row_change == "extra-field":
        for row in rows["left"]:
            row["state"]["extra"] = 5.0
    elif row_change == "later-extra-field":
        rows["left"][-1]["state"]["extra"] = 5.0
    ids = ["left", "right"]
    data = canonical_bytes({"schema_version": sim_shard_coverage.EVIDENCE_VERSION,
        "dynamics_request": request, "dynamics_policy": policy,
        "dynamics_certificate": base64.b64encode(child).decode("ascii"),
        "shard_ids": ids, "shard_rows": rows})
    policy2 = sim_shard_coverage.sim_shard_coverage_policy(trust_roots=["synthetic-shards"])
    request2 = sim_shard_coverage.sim_shard_coverage_request(**common,
        dynamics_request_digest=digest(request), dynamics_policy_digest=digest(policy),
        dynamics_certificate_digest=byte_digest(child), shard_ids_digest=digest(ids),
        shard_rows_digest=digest(rows), evidence_ref=byte_digest(data), policy=policy2)
    child = sim_shard_coverage.build_sim_shard_coverage_certificate(request2, data, policy=policy2)
    relations = [{"op": "eq", "args": [{"var": "right.r"},
                 {"op": "add", "args": [{"var": "left.l"}, 2.0]}]}]
    data = canonical_bytes({"schema_version": sim_shard_relations.EVIDENCE_VERSION,
        "shard_request": request2, "shard_policy": policy2,
        "shard_certificate": base64.b64encode(child).decode("ascii"), "relations": relations})
    policy3 = sim_shard_relations.sim_shard_relations_policy(trust_roots=["synthetic-relations"])
    request3 = sim_shard_relations.sim_shard_relations_request(**common,
        shard_request_digest=digest(request2), shard_policy_digest=digest(policy2),
        shard_certificate_digest=byte_digest(child), relations_digest=digest(relations),
        evidence_ref=byte_digest(data), policy=policy3)
    child = sim_shard_relations.build_sim_shard_relations_certificate(request3, data, policy=policy3)
    private = {name: Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)
               for i, name in enumerate(ids)}
    keys = {name: key.public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex() for name, key in private.items()}
    policy4 = sim_shard_signatures.sim_shard_signatures_policy(required_shards=ids,
        public_keys=keys, trust_roots=["synthetic-selected-shard-keys"])
    parameters = {**common, "relations_request_digest": digest(request3),
        "relations_policy_digest": digest(policy3),
        "relations_certificate_digest": byte_digest(child)}
    signatures = {}
    for name in ids:
        signatures[name] = []
        for index, row in enumerate(rows[name]):
            # Independent domain separator and complete selected message inventory.
            message = b"verifier-current-sim-shard-signature-1\x00" + canonical_bytes({
                "schema_version": "verifier-current-sim-shard-signature-message-1",
                "semantic_version": "verifier-current-object-obligations-1",
                "coordinate": "SIM-4.3",
                "proposition_digest": sim_shard_signatures.PROPOSITION_DIGEST,
                **parameters, "policy_digest": digest(policy4), "shard_id": name,
                "step_index": index, "time": row["time"], "state": row["state"]})
            signatures[name].append(private[name].sign(message).hex())
    if unavailable:
        signatures["left"][0] = None
    if forged:
        signatures["left"][0] = "00" * 64
    data = canonical_bytes({"schema_version": sim_shard_signatures.EVIDENCE_VERSION,
        "relations_request": request3, "relations_policy": policy3,
        "relations_certificate": base64.b64encode(child).decode("ascii"),
        "signatures": signatures})
    request4 = sim_shard_signatures.sim_shard_signatures_request(**parameters,
        evidence_ref=byte_digest(data), policy=policy4)
    child = sim_shard_signatures.build_sim_shard_signatures_certificate(request4, data, policy=policy4)
    return request4, policy4, child, program


def selected(*, row_change: str | None = None, unavailable: bool = False,
             forged: bool = False, limits: dict | None = None):
    module = importlib.import_module("verifier.domains.contracts.sim_surface_partition")
    child_request, child_policy, child, program = signed_child(
        row_change=row_change, unavailable=unavailable, forged=forged)
    surface = {"schema_version": "verifier-current-sim-surface-map-1", "partitions": [
        {"root_variable": "x", "shard_id": "left", "shard_variable": "l",
         "transition_digest": digest(program["x"])},
        {"root_variable": "y", "shard_id": "right", "shard_variable": "r",
         "transition_digest": digest(program["y"])}]}
    evidence = {"schema_version": module.EVIDENCE_VERSION,
        "signatures_request": child_request, "signatures_policy": child_policy,
        "signatures_certificate": base64.b64encode(child).decode("ascii"), "surface": surface}
    policy = module.sim_surface_partition_policy(trust_roots=["externally-selected-finite-partition"])
    request = module.sim_surface_partition_request(
        **{k: child_request[k] for k in ("subject_id", "object_digest", "collection_digest")},
        signatures_request_digest=digest(child_request), signatures_policy_digest=digest(child_policy),
        signatures_certificate_digest=byte_digest(child), surface_digest=digest(surface),
        evidence_ref=digest(evidence), policy=policy, limits=limits)
    return module, request, policy, canonical_bytes(evidence)


def replay(module, request, policy, evidence):
    certificate = module.build_sim_surface_partition_certificate(request, evidence, policy=policy)
    return certificate, module.recheck_sim_surface_partition_certificate(
        certificate, expected_request=request, policy=policy)


def change(request: dict, evidence: bytes, mutate) -> bytes:
    value = json.loads(evidence)
    mutate(value)
    if value["surface"] is not None:
        request["surface_digest"] = digest(value["surface"])
    request["evidence_ref"] = digest(value)
    return canonical_bytes(value)


@pytest.mark.parametrize("row_change", [None, "later-value", "representation", "extra-field", "later-extra-field"])
def test_independent_signed_child_is_replayable(row_change):
    request, policy, child, _ = signed_child(row_change=row_change)
    result = sim_shard_signatures.recheck_sim_shard_signatures_certificate(
        child, expected_request=request, policy=policy)
    assert result["status"] == "PASS"


def test_exact_finite_surface_and_transitions_replay_without_scope_promotion():
    module, request, policy, evidence = selected()
    certificate, native = replay(module, request, policy, evidence)
    public = routes.replay_current_object_certificate(certificate,
        semantic_version=module.SEMANTIC_VERSION, objective="SIM-4.4", represented_kind="SIM",
        expected_request=request, policy=policy)
    assert native["status"] == public["computational_status"] == "PASS"
    assert native["declared_surface_accounting"] == native["declared_transition_attribution"] == "PASS"
    observations = native["evaluation"]["observations"]
    assert observations["root_variables"] == observations["shard_fields"] == 2
    assert observations["mapped_values"] == 6
    assert observations["attributed_transitions"] == observations["observed_changes"] == 4
    for field in ("whole_runtime_surface", "whole_surface_coverage", "sim_tier_4_conformance",
                  "historical_execution", "authority", "object_profile_conformance"):
        assert native[field] == "NOT_ESTABLISHED"
    assert certificate == module.build_sim_surface_partition_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "root-alias", "wrong-field", "extra",
                                     "wrong-transition", "swapped-transition", "empty", "version"])
def test_independently_selected_false_partition_or_attribution_fails(mutation):
    module, request, policy, evidence = selected()
    def mutate(value):
        rows = value["surface"]["partitions"]
        if mutation == "missing": rows.pop()
        elif mutation == "duplicate": rows.append(deepcopy(rows[0]))
        elif mutation == "root-alias": rows[1]["root_variable"] = "x"
        elif mutation == "wrong-field": rows[1]["shard_variable"] = "l"
        elif mutation == "extra": rows.append({**rows[0], "root_variable": "ghost"})
        elif mutation == "wrong-transition": rows[0]["transition_digest"] = "sha256:" + "0" * 64
        elif mutation == "swapped-transition": rows[0]["transition_digest"] = rows[1]["transition_digest"]
        elif mutation == "empty": rows.clear()
        else: value["surface"]["schema_version"] = "other-surface-map"
    evidence = change(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("row_change", ["later-value", "representation", "extra-field", "later-extra-field"])
def test_validly_signed_but_mismapped_retained_values_fail(row_change):
    module, request, policy, evidence = selected(row_change=row_change)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("missing", ["surface", "signatures_certificate", "all-evidence"])
def test_absent_selected_evidence_stays_unknown(missing):
    module, request, policy, evidence = selected()
    evidence = None if missing == "all-evidence" else change(request, evidence,
        lambda value: value.__setitem__(missing, None))
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("unavailable,forged,expected", [(True, False, "UNKNOWN"), (False, True, "FAIL")])
def test_child_is_replayed_with_its_actual_result(unavailable, forged, expected):
    module, request, policy, evidence = selected(unavailable=unavailable, forged=forged)
    assert replay(module, request, policy, evidence)[1]["status"] == expected


@pytest.mark.parametrize("absent_child", [True, False])
def test_known_duplicate_attribution_is_not_hidden_by_unavailable_child(absent_child):
    module, request, policy, evidence = selected(unavailable=not absent_child)
    def mutate(value):
        value["surface"]["partitions"].append(deepcopy(value["surface"]["partitions"][0]))
        if absent_child:
            value["signatures_certificate"] = None
    evidence = change(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest",
    "signatures_request_digest", "signatures_policy_digest", "signatures_certificate_digest", "surface_digest"])
def test_external_selection_cannot_be_substituted(field):
    module, request, policy, evidence = selected()
    request[field] = "other-sim" if field == "subject_id" else "sha256:" + "0" * 64
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_carried_positive_verdict_is_rejected_even_after_rehash():
    module, request, policy, evidence = selected(row_change="later-value")
    certificate, result = replay(module, request, policy, evidence)
    assert result["status"] == "FAIL"
    value = json.loads(certificate)
    value["result"]["status"] = value["result"]["declared_surface_accounting"] = "PASS"
    value.pop("digest")
    value["digest"] = digest(value)
    with pytest.raises(module.SimSurfacePartitionError):
        module.recheck_sim_surface_partition_certificate(canonical_bytes(value),
            expected_request=request, policy=policy)


@pytest.mark.parametrize("limits", [{"max_operations": 1}, {"max_items": 1}])
def test_exhausted_selected_bounds_stay_unknown(limits):
    module, request, policy, evidence = selected(limits=limits)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("source", ["CURRENT_SIM_SURFACE_PARTITION.md", "CURRENT_SIM_SHARD_SIGNATURES.md",
    "sim_shard_signatures.py", "sim_dynamics.py"])
def test_installed_dependency_bytes_are_bound(monkeypatch, source):
    module = importlib.import_module("verifier.domains.contracts.sim_surface_partition")
    before = module.mechanism_digest()
    original = Path.read_bytes
    def changed(path):
        value = original(path)
        return value + b"\n# independent digest mutation\n" if path.name == source else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert module.mechanism_digest() != before


def polish_selection(module, request, policy, certificate, evidence):
    """Recover objects from the selected root evidence, not a second fixture."""
    retained = json.loads(evidence)
    for prefix in ("signatures", "relations", "shard", "dynamics"):
        child_request = retained[prefix + "_request"]
        child = json.loads(base64.b64decode(retained[prefix + "_certificate"]))
        retained = json.loads(base64.b64decode(child["evidence_payloads"][child_request["evidence_ref"]]))
    objects = retained["objects"]
    cert_digest = byte_digest(certificate)
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {cert_digest: certificate.decode("utf-8")}}
    requirements = [{"object_id": item["object_id"], "tier": tier,
        "applicability": "REQUIRED", "rationale": "selected finite declaration",
        "objectives": []} for item in objects for tier in range(1, 10)]
    next(row for row in requirements if row["object_id"] == "sim" and row["tier"] == 4)["objectives"] = [{
        "semantic_version": module.SEMANTIC_VERSION, "coordinate": module.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": cert_digest}]
    selected_request = {"schema_version": "verifier-polish-request-1", "root_id": "sim",
        "collection_digest": request["collection_digest"], "bundle_digest": digest(bundle),
        "requirements": requirements}
    return bundle, selected_request


def test_actual_polish_replays_selected_surface_without_positive_issuance():
    from verifier.runtime.polish import assess_polish

    module, request, policy, evidence = selected()
    certificate, _ = replay(module, request, policy, evidence)
    bundle, selected_request = polish_selection(module, request, policy, certificate, evidence)
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("source", ["sim_surface_partition.py", "CURRENT_SIM_SURFACE_PARTITION.md"])
def test_new_checker_and_spec_are_bound_by_polish(monkeypatch, source):
    from verifier.runtime import polish

    before = polish.mechanism_digest()
    original = Path.read_bytes
    def changed(path):
        value = original(path)
        return value + b"\n# independent polish digest mutation\n" if path.name == source else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_actual_canonical_surface_certificate_refuses_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError)

    module, request, policy, evidence = selected()
    certificate, _ = replay(module, request, policy, evidence)
    value = json.loads(certificate)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("SIM", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "selected-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


def test_rehashed_forged_child_verdict_is_refuted():
    module, request, policy, evidence = selected(forged=True)
    def mutate(value):
        child = json.loads(base64.b64decode(value["signatures_certificate"]))
        assert child["result"]["status"] == "FAIL"
        child["result"]["status"] = "PASS"
        child.pop("digest")
        child["digest"] = digest(child)
        raw = canonical_bytes(child)
        value["signatures_certificate"] = base64.b64encode(raw).decode("ascii")
        request["signatures_certificate_digest"] = byte_digest(raw)
    evidence = change(request, evidence, mutate)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("semantic,kind", [("legacy-sim-domain-1", "SIM"),
    ("verifier-current-object-obligations-1", "BOT")])
def test_legacy_selector_and_wrong_kind_cannot_claim_current_accounting(semantic, kind):
    module, request, policy, evidence = selected()
    certificate, _ = replay(module, request, policy, evidence)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(certificate,
            semantic_version=semantic, objective=module.COORDINATE,
            represented_kind=kind, expected_request=request, policy=policy)


def test_surface_accounting_is_available_through_actual_command(tmp_path, capsys):
    from verifier.runtime.public_cli import main

    module, request, policy, evidence = selected()
    certificate, _ = replay(module, request, policy, evidence)
    paths = [tmp_path / name for name in ("certificate.json", "request.json", "policy.json")]
    for path, data in zip(paths, (certificate, canonical_bytes(request), canonical_bytes(policy))):
        path.write_bytes(data)
    assert main(["current-object", "check", str(paths[0]), "--semantic-version", module.SEMANTIC_VERSION,
        "--objective", module.COORDINATE, "--represented-kind", "SIM", "--request", str(paths[1]),
        "--policy", str(paths[2]), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["whole_runtime_surface"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("forgery,expected", [(None, "UNKNOWN"), ("authority", "FAIL"),
    ("count", "FAIL"), ("digest", "FAIL"), ("absent-signature", "FAIL")])
def test_real_backend_absence_preserves_unknown_and_known_child_refutations(tmp_path, forgery, expected):
    module, request, policy, evidence = selected()
    value = json.loads(evidence)
    child = json.loads(base64.b64decode(value["signatures_certificate"]))
    if forgery == "authority":
        child["result"]["authority"] = "PASS"
    elif forgery == "count":
        child["result"]["evaluation"]["observations"]["verified_signatures"] = 1000
    elif forgery == "absent-signature":
        child_request = value["signatures_request"]
        child_data = json.loads(base64.b64decode(child["evidence_payloads"][child_request["evidence_ref"]]))
        child_data["signatures"]["left"][0] = None
        child_request["evidence_ref"] = digest(child_data)
        child["evidence_payloads"] = {child_request["evidence_ref"]:
            base64.b64encode(canonical_bytes(child_data)).decode("ascii")}
        child["request"] = child_request
        child["evidence_refs"] = [child_request["evidence_ref"]]
        request["signatures_request_digest"] = digest(child_request)
        # A forged carried PASS remains detectable from the absent required row,
        # even if the attacker repairs the visible request/evidence bindings.
        child["result"]["evaluation"]["evidence_refs"] = [child_request["evidence_ref"]]
        binding = {"subject_id": child_request["subject_id"], "predicate": "SIM-4.3",
            "expected": True, "mechanism_id": policy_child_id(value),
            "mechanism_digest": value["signatures_policy"]["mechanism_digest"],
            "evidence_refs": [child_request["evidence_ref"]],
            "trust_roots": value["signatures_policy"]["trust_roots"],
            "bounds": {"max_evidence_items": 1,
                       "max_evidence_bytes": child_request["limits"]["max_evidence_bytes"]},
            "parameters": {"request_digest": digest(child_request)}}
        child["result"]["evaluation"]["binding_digest"] = digest(binding).split(":", 1)[1]
        child["result"]["evaluation"]["observed_evidence_bytes"] = len(canonical_bytes(child_data))
    if forgery:
        child.pop("digest")
        child["digest"] = digest(child) if forgery != "digest" else "sha256:" + "0" * 64
        raw = canonical_bytes(child)
        value["signatures_certificate"] = base64.b64encode(raw).decode("ascii")
        request["signatures_certificate_digest"] = byte_digest(raw)
        request["evidence_ref"] = digest(value)
        evidence = canonical_bytes(value)
    for name, data in (("request.json", canonical_bytes(request)),
                       ("policy.json", canonical_bytes(policy)), ("evidence.json", evidence)):
        (tmp_path / name).write_bytes(data)
    code = '''
import json,sys
from pathlib import Path
from verifier.domains.contracts import sim_surface_partition as surface
root=Path(sys.argv[1])
assert "cryptography" not in sys.modules
request=json.loads((root/"request.json").read_bytes())
policy=json.loads((root/"policy.json").read_bytes())
certificate=surface.build_sim_surface_partition_certificate(request,(root/"evidence.json").read_bytes(),policy=policy)
result=surface.recheck_sim_surface_partition_certificate(certificate,expected_request=request,policy=policy)
assert "cryptography" not in sys.modules
print(json.dumps(result),flush=True)
'''
    print("REAL STANDARD-LIBRARY-ONLY CHILD REPLAY", forgery, flush=True)
    run = subprocess.run([sys.executable, "-u", "-S", "-c", code, str(tmp_path)],
        capture_output=True, text=True, timeout=10)
    print(run.stdout + run.stderr, flush=True)
    assert run.returncode == 0
    result = json.loads(run.stdout)
    assert result["status"] == expected
    if forgery == "absent-signature":
        assert "absent required" in result["evaluation"]["details"]


def policy_child_id(value: dict) -> str:
    return value["signatures_policy"]["mechanism_id"]
