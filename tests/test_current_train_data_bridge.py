"""A selected retained DATA shard must actually bind the TRAIN batch view.

This specimen checks selected record bytes, not historical execution.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import data_checks, train_data_bridge


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def selection(*, substituted_data: bool = False, missing_child: bool = False,
              false_inventory: bool = False, unknown_data_child: bool = False,
              limits: dict | None = None):
    bridge = train_data_bridge
    specimen = runpy.run_path(str(Path(__file__).with_name("test_current_train_checks.py")))
    train, train_request, train_policy, train_evidence = specimen["inputs"]("lineage")
    train_certificate = train.build_train_checks_certificate(
        train_request, train_evidence, policy=train_policy,
    )
    assert train.recheck_train_checks_certificate(
        train_certificate, expected_request=train_request, policy=train_policy,
    )["status"] == "PASS"
    train_bundle = json.loads(train_evidence)
    batch_view = next(row for row in train_bundle["objects"] if row["object_id"] == "batches")
    batches = batch_view["payload"]["batches"]
    rows = [batches[key] for key in sorted(batches)]
    if substituted_data:
        rows = [[[{"input": [1], "target": [99]}]]]
    commitments = {"training": {
        "digest": digest(rows), "records": len(rows), "bytes": len(canonical_bytes(rows)),
        "record_digests": [digest(row) for row in rows], "merkle_root": digest(rows[0]),
    }}
    if false_inventory:
        commitments["training"]["record_digests"] = [digest("different-record")]
    data_subject = NamespaceObject.create("retained-shard-view", "DATA", {"shards": commitments})
    data_evidence = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [data_subject.to_dict()],
        "inputs": {"shards": {"training": rows}},
    })
    data_policy = data_checks.data_checks_policy(trust_roots=["selected-shard-data"])
    data_request = data_checks.data_checks_request(
        check="inventory", subject_id=data_subject.object_id,
        object_digest=data_subject.digest,
        collection_digest=composition_digest([data_subject]),
        evidence_ref=digest_bytes(data_evidence), policy=data_policy,
    )
    data_certificate = data_checks.build_data_checks_certificate(
        data_request, None if unknown_data_child else data_evidence, policy=data_policy,
    )
    assert data_checks.recheck_data_checks_certificate(
        data_certificate, expected_request=data_request, policy=data_policy,
    )["status"] == ("UNKNOWN" if unknown_data_child else "FAIL" if false_inventory else "PASS")
    parent_evidence = canonical_bytes({
        "schema_version": bridge.EVIDENCE_VERSION,
        "train_certificate_b64": "" if missing_child else base64.b64encode(train_certificate).decode("ascii"),
        "data_certificate_b64": base64.b64encode(data_certificate).decode("ascii"),
    })
    policy = bridge.train_data_bridge_policy(trust_roots=["selected-retained-link"])
    request = bridge.train_data_bridge_request(
        train_request=train_request, train_policy=train_policy,
        train_certificate_digest=digest_bytes(train_certificate),
        data_request=data_request, data_policy=data_policy,
        data_certificate_digest=digest_bytes(data_certificate),
        batch_view_id="batches", batch_view_digest=NamespaceObject.create(**batch_view).digest,
        shard_ids=["training"], evidence_ref=digest_bytes(parent_evidence),
        policy=policy, limits=limits,
    )
    return bridge, request, policy, parent_evidence


def replay(*args):
    bridge, request, policy, evidence = args
    certificate = bridge.build_train_data_bridge_certificate(request, evidence, policy=policy)
    return bridge.recheck_train_data_bridge_certificate(
        certificate, expected_request=request, policy=policy,
    )["status"]


def test_exact_linked_native_children_replay():
    assert replay(*selection()) == "PASS"


def test_individually_valid_substituted_data_is_refuted_by_bridge():
    assert replay(*selection(substituted_data=True)) == "FAIL"


def test_missing_selected_train_child_is_unknown():
    assert replay(*selection(missing_child=True)) == "UNKNOWN"


def test_false_data_child_remains_false():
    assert replay(*selection(false_inventory=True)) == "FAIL"


def test_unknown_data_child_remains_unknown():
    assert replay(*selection(unknown_data_child=True)) == "UNKNOWN"


def test_one_under_child_bound_is_unknown():
    bridge, request, policy, evidence = selection()
    train_child = base64.b64decode(json.loads(evidence)["train_certificate_b64"])
    assert replay(*selection(limits={"max_train_certificate_bytes": len(train_child) - 1})) == "UNKNOWN"


def test_rehashed_forged_child_result_cannot_pass():
    bridge, request, policy, evidence = selection()
    changed = json.loads(evidence)
    child = json.loads(base64.b64decode(changed["train_certificate_b64"]))
    child["result"]["status"] = "FAIL"
    child["digest"] = digest({key: value for key, value in child.items() if key != "digest"})
    child_bytes = canonical_bytes(child)
    changed["train_certificate_b64"] = base64.b64encode(child_bytes).decode("ascii")
    changed_evidence = canonical_bytes(changed)
    rebound = deepcopy(request)
    rebound["train_certificate_digest"] = digest_bytes(child_bytes)
    rebound["evidence_ref"] = digest_bytes(changed_evidence)
    assert replay(bridge, rebound, policy, changed_evidence) == "FAIL"


def test_rehashed_forged_false_child_pass_cannot_upgrade_inventory():
    bridge, request, policy, evidence = selection(false_inventory=True)
    changed = json.loads(evidence)
    child = json.loads(base64.b64decode(changed["data_certificate_b64"]))
    assert child["result"]["status"] == "FAIL"
    child["result"]["status"] = "PASS"
    child["digest"] = digest({key: value for key, value in child.items() if key != "digest"})
    child_bytes = canonical_bytes(child)
    changed["data_certificate_b64"] = base64.b64encode(child_bytes).decode("ascii")
    changed_evidence = canonical_bytes(changed)
    rebound = deepcopy(request)
    rebound["data_certificate_digest"] = digest_bytes(child_bytes)
    rebound["evidence_ref"] = digest_bytes(changed_evidence)
    assert replay(bridge, rebound, policy, changed_evidence) == "FAIL"


def test_changed_shard_selection_cannot_replay_existing_certificate():
    bridge, request, policy, evidence = selection()
    certificate = bridge.build_train_data_bridge_certificate(request, evidence, policy=policy)
    changed = deepcopy(request)
    changed["shard_ids"] = ["other"]
    with pytest.raises(bridge.TrainDataBridgeError):
        bridge.recheck_train_data_bridge_certificate(
            certificate, expected_request=changed, policy=policy,
        )


def test_current_public_route_replays_selected_bridge(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    bridge, request, policy, evidence = selection()
    certificate = bridge.build_train_data_bridge_certificate(request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=bridge.SEMANTIC_VERSION,
        objective=bridge.COORDINATE, represented_kind="TRAIN",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    for name, raw in (("certificate", certificate), ("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy))):
        (tmp_path / (name + ".json")).write_bytes(raw)
    assert main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", bridge.SEMANTIC_VERSION,
        "--objective", bridge.COORDINATE, "--represented-kind", "TRAIN",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_bridge_cannot_redact_child_evidence():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    bridge, request, policy, evidence = selection()
    envelope = json.loads(bridge.build_train_data_bridge_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in envelope if key != "evidence_payloads")
    surface = DisclosureSurface("TRAIN", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(envelope, surface, bounds, context)
