"""Model reproducibility (MODEL), training-run specification (TRAIN), and
dataset integrity and lineage (DATA) need an exact replayed bridge.

The specimen establishes retained provenance, not historical execution or
derivation of model weights. Counts and fixture scalars are dimensionless.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
from types import ModuleType
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import (data_checks, model_data_citation,
    model_data_lineage, train_checks, train_data_bridge)


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def selected(*, substituted_shard: bool = False, other_model_train: bool = False,
             missing_bridge: bool = False, limits: dict[str, Any] | None = None
             ) -> tuple[ModuleType, dict[str, Any], dict[str, Any], bytes]:
    lineage = model_data_lineage
    specimen = runpy.run_path(str(Path(__file__).with_name("test_current_train_checks.py")))
    _, _, _, original = specimen["inputs"]("lineage")
    original_bundle = json.loads(original)
    objects = [NamespaceObject.create(**row) for row in original_bundle["objects"]]
    batch_view = next(item for item in objects if item.object_id == "batches")
    train = next(item for item in objects if item.object_id == "training")
    batch_map = batch_view.payload["batches"]
    rows = [batch_map[key] for key in sorted(batch_map)]
    if substituted_shard:
        rows = [[[{"input": [1], "target": [99]}]]]
    commitments = {"training": {
        "digest": digest(rows), "records": len(rows), "bytes": len(canonical_bytes(rows)),
        "record_digests": [digest(row) for row in rows], "merkle_root": digest(rows[0]),
    }}
    inventory = NamespaceObject.create("dataset", "DATA", {"shards": commitments})
    model_train_id = "other-training" if other_model_train else train.object_id
    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": [inventory.object_id],
        "train": [model_train_id], "bench": ["loss"],
        "events": ["step-0", "step-1"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects.extend([
        inventory, model,
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ])
    if other_model_train:
        objects.append(NamespaceObject.create("other-training", "TRAIN", train.payload,
                                             dict(train.operands)))
    collection_digest = composition_digest(objects)
    train_evidence = canonical_bytes({
        "schema_version": train_checks.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": original_bundle["inputs"],
    })
    train_policy = train_checks.train_checks_policy(trust_roots=["selected-model-train"])
    train_request = train_checks.train_checks_request(
        check="lineage", subject_id=train.object_id,
        object_digest=train.digest, collection_digest=collection_digest,
        evidence_ref=digest_bytes(train_evidence), policy=train_policy,
    )
    train_certificate = train_checks.build_train_checks_certificate(
        train_request, train_evidence, policy=train_policy,
    )
    assert train_checks.recheck_train_checks_certificate(
        train_certificate, expected_request=train_request, policy=train_policy,
    )["status"] == "PASS"

    data_evidence = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [inventory.to_dict()],
        "inputs": {"shards": {"training": rows}},
    })
    data_policy = data_checks.data_checks_policy(trust_roots=["selected-model-data"])
    data_request = data_checks.data_checks_request(
        check="inventory", subject_id=inventory.object_id,
        object_digest=inventory.digest,
        collection_digest=composition_digest([inventory]),
        evidence_ref=digest_bytes(data_evidence), policy=data_policy,
    )
    data_certificate = data_checks.build_data_checks_certificate(
        data_request, data_evidence, policy=data_policy,
    )
    assert data_checks.recheck_data_checks_certificate(
        data_certificate, expected_request=data_request, policy=data_policy,
    )["status"] == "PASS"

    model_data_evidence = canonical_bytes({
        "schema_version": model_data_citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"data_certificate_b64": base64.b64encode(data_certificate).decode("ascii")},
    })
    model_data_policy = model_data_citation.model_data_policy(
        trust_roots=["selected-model-data-citation"],
    )
    model_data_request = model_data_citation.model_data_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection_digest,
        evidence_ref=digest_bytes(model_data_evidence), policy=model_data_policy,
        data_subject_id=inventory.object_id, data_object_digest=inventory.digest,
        data_certificate_digest=digest_bytes(data_certificate),
        data_request=data_request, data_policy=data_policy,
    )
    model_data_certificate = model_data_citation.build_model_data_certificate(
        model_data_request, model_data_evidence, policy=model_data_policy,
    )
    assert model_data_citation.recheck_model_data_certificate(
        model_data_certificate, expected_request=model_data_request,
        policy=model_data_policy,
    )["status"] == "PASS"

    bridge_evidence = canonical_bytes({
        "schema_version": train_data_bridge.EVIDENCE_VERSION,
        "train_certificate_b64": base64.b64encode(train_certificate).decode("ascii"),
        "data_certificate_b64": base64.b64encode(data_certificate).decode("ascii"),
    })
    bridge_policy = train_data_bridge.train_data_bridge_policy(
        trust_roots=["selected-model-bridge"],
    )
    bridge_request = train_data_bridge.train_data_bridge_request(
        train_request=train_request, train_policy=train_policy,
        train_certificate_digest=digest_bytes(train_certificate),
        data_request=data_request, data_policy=data_policy,
        data_certificate_digest=digest_bytes(data_certificate),
        batch_view_id=batch_view.object_id, batch_view_digest=batch_view.digest,
        shard_ids=["training"], evidence_ref=digest_bytes(bridge_evidence),
        policy=bridge_policy,
    )
    bridge_certificate = train_data_bridge.build_train_data_bridge_certificate(
        bridge_request, bridge_evidence, policy=bridge_policy,
    )
    assert train_data_bridge.recheck_train_data_bridge_certificate(
        bridge_certificate, expected_request=bridge_request, policy=bridge_policy,
    )["status"] == ("FAIL" if substituted_shard else "PASS")

    evidence = canonical_bytes({
        "schema_version": lineage.EVIDENCE_VERSION,
        "model_data_certificate_b64": base64.b64encode(model_data_certificate).decode("ascii"),
        "bridge_certificate_b64": "" if missing_bridge else base64.b64encode(bridge_certificate).decode("ascii"),
    })
    policy = lineage.model_data_lineage_policy(trust_roots=["selected-model-lineage"])
    request = lineage.model_data_lineage_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection_digest, evidence_ref=digest_bytes(evidence),
        train_subject_id=train.object_id, train_object_digest=train.digest,
        model_data_subject_id=inventory.object_id,
        model_data_object_digest=inventory.digest,
        batch_view_subject_id=batch_view.object_id,
        batch_view_object_digest=batch_view.digest,
        model_data_certificate_digest=digest_bytes(model_data_certificate),
        model_data_request=model_data_request, model_data_policy=model_data_policy,
        bridge_certificate_digest=digest_bytes(bridge_certificate),
        bridge_request=bridge_request, bridge_policy=bridge_policy,
        policy=policy, limits=limits,
    )
    return lineage, request, policy, evidence


def replay(lineage: ModuleType, request: dict[str, Any],
           policy: dict[str, Any], evidence: bytes) -> str:
    certificate = lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)
    return lineage.recheck_model_data_lineage_certificate(
        certificate, expected_request=request, policy=policy,
    )["status"]


def test_exact_model_train_two_data_view_bridge_replays() -> None:
    assert replay(*selected()) == "PASS"


def test_individually_valid_model_data_and_false_bridge_cannot_promote() -> None:
    assert replay(*selected(substituted_shard=True)) == "FAIL"


def test_other_valid_train_cannot_fill_selected_model_operand() -> None:
    assert replay(*selected(other_model_train=True)) == "FAIL"


def test_missing_selected_bridge_is_unknown() -> None:
    assert replay(*selected(missing_bridge=True)) == "UNKNOWN"


def test_external_selected_bridge_digest_cannot_be_substituted() -> None:
    lineage, request, policy, evidence = selected()
    certificate = lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)
    changed = deepcopy(request)
    changed["bridge_certificate_digest"] = digest_bytes(b"another bridge")
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.recheck_model_data_lineage_certificate(
            certificate, expected_request=changed, policy=policy,
        )


def test_same_inventory_child_selection_is_required_on_both_paths() -> None:
    lineage, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["bridge_request"]["data_certificate_digest"] = digest_bytes(b"other inventory")
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.build_model_data_lineage_certificate(changed, evidence, policy=policy)


def test_rehashed_forged_bridge_result_cannot_promote() -> None:
    lineage, request, policy, evidence = selected()
    changed = json.loads(evidence)
    bridge = json.loads(base64.b64decode(changed["bridge_certificate_b64"]))
    bridge["result"]["status"] = "FAIL"
    bridge["digest"] = digest({key: value for key, value in bridge.items() if key != "digest"})
    bridge_bytes = canonical_bytes(bridge)
    changed["bridge_certificate_b64"] = base64.b64encode(bridge_bytes).decode("ascii")
    changed_bytes = canonical_bytes(changed)
    rebound = deepcopy(request)
    rebound["bridge_certificate_digest"] = digest_bytes(bridge_bytes)
    rebound["evidence_ref"] = digest_bytes(changed_bytes)
    assert replay(lineage, rebound, policy, changed_bytes) == "FAIL"


def test_forged_parent_result_and_changed_source_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    lineage, request, policy, evidence = selected()
    cert = lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)
    changed = json.loads(cert)
    changed["result"]["model_weight_derivation"] = "ESTABLISHED"
    changed["digest"] = digest({key: value for key, value in changed.items() if key != "digest"})
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.recheck_model_data_lineage_certificate(
            canonical_bytes(changed), expected_request=request, policy=policy,
        )
    monkeypatch.setattr(lineage, "mechanism_digest", lambda: digest_bytes(b"changed source"))
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.recheck_model_data_lineage_certificate(
            cert, expected_request=request, policy=policy,
        )


def test_one_under_selected_bridge_bound_is_unknown() -> None:
    lineage, request, policy, evidence = selected()
    bridge = base64.b64decode(json.loads(evidence)["bridge_certificate_b64"])
    assert replay(*selected(limits={"max_bridge_certificate_bytes": len(bridge) - 1})) == "UNKNOWN"


def test_public_route_replays_selected_lineage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    lineage, request, policy, evidence = selected()
    certificate = lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=lineage.SEMANTIC_VERSION,
        objective=lineage.COORDINATE, represented_kind="MODEL",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["model_weight_derivation"] == "NOT_ESTABLISHED"
    for stem, raw in (("certificate", certificate), ("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy))):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    assert main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", lineage.SEMANTIC_VERSION,
        "--objective", lineage.COORDINATE, "--represented-kind", "MODEL",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_lineage_cannot_redact_retained_children() -> None:
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    lineage, request, policy, evidence = selected()
    envelope = json.loads(lineage.build_model_data_lineage_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in envelope if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(envelope, surface, bounds, context)
