"""Select an exact MODEL-to-TRAIN citation and challenge its retained prerequisites."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import data_checks, model_data_citation
from verifier.domains.contracts import model_train_citation as citation


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def selected(*, retained_row=None, declared_row=None, child_evidence=True,
             parent_inputs=True, model_train_id="training",
             train_data_id="dataset"):
    declared_row = declared_row or {"id": "sample-1", "text": "selected bytes"}
    retained_row = retained_row or declared_row
    declared_rows = [declared_row]
    row_digest = digest(canonical_bytes(declared_row))
    dataset_payload = {"shards": {"training": {
        "digest": digest(canonical_bytes(declared_rows)),
        "records": 1,
        "bytes": len(canonical_bytes(declared_rows)),
        "record_digests": [row_digest],
        "merkle_root": row_digest,
    }}}
    dataset = NamespaceObject.create("dataset", "DATA", dataset_payload)
    data_evidence = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [dataset.to_dict()],
        "inputs": {"shards": {"training": [retained_row]}},
    })
    data_policy = data_checks.data_checks_policy(trust_roots=["selected-open-data"])
    data_request = data_checks.data_checks_request(
        check="inventory", subject_id=dataset.object_id,
        object_digest=dataset.digest,
        collection_digest=composition_digest([dataset]),
        evidence_ref=digest(data_evidence), policy=data_policy,
    )
    data_certificate = data_checks.build_data_checks_certificate(
        data_request, data_evidence if child_evidence else None,
        policy=data_policy,
    )
    training_roles = {
        "arch": ["architecture"], "data": [train_data_id],
        "bench": ["benchmark"], "events": ["event"],
    }
    training = NamespaceObject.create("training", "TRAIN", {}, training_roles)
    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": ["dataset"],
        "events": ["event"], "bench": ["benchmark"],
        "train": [model_train_id], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        model, training, dataset,
        NamespaceObject.create("architecture", "ARCH", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {
            "data": ["dataset"], "verifier": ["checker"],
        }),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("event", "EVENT", {}, {
            "time": ["time"], "space": ["space"], "meaning": ["meaning"],
        }),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    if model_train_id != "training":
        objects.append(NamespaceObject.create(
            model_train_id, "TRAIN", {}, training_roles,
        ))
    if train_data_id != "dataset":
        objects.append(NamespaceObject.create(train_data_id, "DATA", dataset_payload))
    collection = composition_digest(objects)
    model_data_evidence = canonical_bytes({
        "schema_version": model_data_citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"data_certificate_b64": base64.b64encode(data_certificate).decode("ascii")},
    })
    model_data_policy = model_data_citation.model_data_policy(
        trust_roots=["selected-open-model-data"],
    )
    model_data_request = model_data_citation.model_data_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection, evidence_ref=digest(model_data_evidence),
        policy=model_data_policy, data_subject_id=dataset.object_id,
        data_object_digest=dataset.digest,
        data_certificate_digest=digest(data_certificate),
        data_request=data_request, data_policy=data_policy,
    )
    model_data_certificate = model_data_citation.build_model_data_certificate(
        model_data_request, model_data_evidence, policy=model_data_policy,
    )
    evidence = canonical_bytes({
        "schema_version": citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"model_data_certificate_b64": base64.b64encode(
            model_data_certificate,
        ).decode("ascii")} if parent_inputs else None,
    })
    policy = citation.model_train_policy(trust_roots=["selected-open-model-train"])
    request = citation.model_train_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection, evidence_ref=digest(evidence),
        policy=policy, train_subject_id=training.object_id,
        train_object_digest=training.digest,
        data_subject_id=dataset.object_id,
        data_object_digest=dataset.digest,
        model_data_certificate_digest=digest(model_data_certificate),
        model_data_request=model_data_request,
        model_data_policy=model_data_policy,
    )
    return request, policy, evidence


def replay(request, policy, evidence):
    certificate = citation.build_model_train_certificate(request, evidence, policy=policy)
    result = citation.recheck_model_train_certificate(
        certificate, expected_request=request, policy=policy,
    )
    return certificate, result


def test_exact_model_train_data_citation_replays():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["model_data_prerequisite"] == "REPLAYED_LOCAL"
    assert result["train_checkpoint_inventory"] == "NOT_ESTABLISHED"
    assert result["actual_training_execution"] == "NOT_ESTABLISHED"
    assert result["model_weight_derivation"] == "NOT_ESTABLISHED"
    assert certificate == citation.build_model_train_certificate(
        request, evidence, policy=policy,
    )


def test_false_data_inventory_stays_false_through_two_citations():
    result = replay(*selected(
        retained_row={"id": "different", "text": "different bytes"},
        declared_row={"id": "sample-1", "text": "selected bytes"},
    ))[1]
    assert result["status"] == "FAIL"


def test_unknown_child_inventory_stays_unknown():
    assert replay(*selected(child_evidence=False))[1]["status"] == "UNKNOWN"


def test_absent_parent_child_certificate_is_unknown():
    assert replay(*selected(parent_inputs=False))[1]["status"] == "UNKNOWN"


def test_child_certificate_bound_one_byte_too_small_is_unknown():
    request, policy, evidence = selected()
    child = base64.b64decode(json.loads(evidence)["inputs"]["model_data_certificate_b64"])
    changed = deepcopy(request)
    changed["limits"]["max_child_certificate_bytes"] = len(child) - 1
    assert replay(changed, policy, evidence)[1]["status"] == "UNKNOWN"


def test_noncanonical_child_encoding_is_refuted():
    request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["inputs"]["model_data_certificate_b64"] += "\n"
    changed_bytes = canonical_bytes(changed)
    changed_request = deepcopy(request)
    changed_request["evidence_ref"] = digest(changed_bytes)
    assert replay(changed_request, policy, changed_bytes)[1]["status"] == "FAIL"


def test_other_valid_train_operand_does_not_fill_selected_citation():
    result = replay(*selected(model_train_id="other-training"))[1]
    assert result["status"] == "FAIL"
    assert "MODEL train operand differs" in result["evaluation"]["details"]


def test_train_data_operand_must_match_model_data_citation():
    result = replay(*selected(train_data_id="other-dataset"))[1]
    assert result["status"] == "FAIL"
    assert "TRAIN data operand differs" in result["evaluation"]["details"]


def test_external_train_digest_substitution_is_rejected():
    request, policy, evidence = selected()
    certificate = citation.build_model_train_certificate(request, evidence, policy=policy)
    changed = deepcopy(request)
    changed["train_object_digest"] = digest(b"other training object")
    with pytest.raises(citation.ModelTrainError):
        citation.recheck_model_train_certificate(
            certificate, expected_request=changed, policy=policy,
        )


def test_other_child_objective_cannot_fill_model_data_prerequisite():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["model_data_request"]["coordinate"] = "MODEL-3.1"
    with pytest.raises(citation.ModelTrainError):
        citation.build_model_train_certificate(changed, evidence, policy=policy)


def test_other_child_collection_cannot_fill_same_collection_prerequisite():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["model_data_request"]["collection_digest"] = digest(b"other collection")
    with pytest.raises(citation.ModelTrainError):
        citation.build_model_train_certificate(changed, evidence, policy=policy)


def test_recursive_child_selection_is_rejected():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["model_data_request"]["recursive"] = changed["model_data_request"]
    with pytest.raises(citation.ModelTrainError):
        citation.build_model_train_certificate(changed, evidence, policy=policy)


def test_forged_child_pass_cannot_upgrade_false_inventory():
    request, policy, evidence = selected(
        retained_row={"id": "different", "text": "different bytes"},
        declared_row={"id": "sample-1", "text": "selected bytes"},
    )
    changed_evidence = json.loads(evidence)
    child = json.loads(base64.b64decode(
        changed_evidence["inputs"]["model_data_certificate_b64"],
    ))
    assert child["result"]["status"] == "FAIL"
    child["result"]["status"] = "PASS"
    child["digest"] = digest(canonical_bytes({
        key: value for key, value in child.items() if key != "digest"
    }))
    child_bytes = canonical_bytes(child)
    changed_evidence["inputs"]["model_data_certificate_b64"] = base64.b64encode(
        child_bytes,
    ).decode("ascii")
    changed_bytes = canonical_bytes(changed_evidence)
    changed_request = deepcopy(request)
    changed_request["model_data_certificate_digest"] = digest(child_bytes)
    changed_request["evidence_ref"] = digest(changed_bytes)
    assert replay(changed_request, policy, changed_bytes)[1]["status"] == "FAIL"


def test_rehashed_parent_result_substitution_is_rejected():
    request, policy, evidence = selected()
    envelope = json.loads(citation.build_model_train_certificate(
        request, evidence, policy=policy,
    ))
    envelope["result"]["model_weight_derivation"] = "ESTABLISHED"
    envelope["digest"] = digest(canonical_bytes({
        key: value for key, value in envelope.items() if key != "digest"
    }))
    with pytest.raises(citation.ModelTrainError):
        citation.recheck_model_train_certificate(
            canonical_bytes(envelope), expected_request=request, policy=policy,
        )


def test_changed_checker_source_invalidates_selected_parent_policy(monkeypatch):
    request, policy, evidence = selected()
    certificate = citation.build_model_train_certificate(request, evidence, policy=policy)
    monkeypatch.setattr(citation, "mechanism_digest", lambda: digest(b"changed source"))
    with pytest.raises(citation.ModelTrainError):
        citation.recheck_model_train_certificate(
            certificate, expected_request=request, policy=policy,
        )


def test_public_route_replays_exact_model_train_citation(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate = citation.build_model_train_certificate(request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=citation.SEMANTIC_VERSION,
        objective=citation.COORDINATE, represented_kind="MODEL",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["model_weight_derivation"] == "NOT_ESTABLISHED"
    for stem, raw in (
        ("certificate", certificate),
        ("request", canonical_bytes(request)),
        ("policy", canonical_bytes(policy)),
    ):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    assert main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", citation.SEMANTIC_VERSION,
        "--objective", citation.COORDINATE, "--represented-kind", "MODEL",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_parent_cannot_hide_retained_child():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    request, policy, evidence = selected()
    envelope = json.loads(citation.build_model_train_certificate(
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
