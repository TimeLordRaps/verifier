"""Independently select a MODEL training-data citation and replay DATA inventory."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import data_checks
from verifier.domains.contracts import model_data_citation as citation


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def selected(*, retained_row=None, declared_row=None, include_inputs=True,
             include_evidence=True, model_data_id="dataset"):
    retained_row = retained_row or {"id": "sample-1", "text": "open training sample"}
    declared_row = declared_row or retained_row
    rows = [declared_row]
    row_digest = digest(canonical_bytes(declared_row))
    artifact = {"shards": {"training": {
        "digest": digest(canonical_bytes(rows)),
        "records": 1,
        "bytes": len(canonical_bytes(rows)),
        "record_digests": [row_digest],
        "merkle_root": row_digest,
    }}}
    dataset = NamespaceObject.create("dataset", "DATA", artifact)
    child_objects = [dataset]
    child_evidence = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [dataset.to_dict()],
        "inputs": {"shards": {"training": [retained_row]}},
    })
    child_policy = data_checks.data_checks_policy(trust_roots=["selected-open-data"])
    child_request = data_checks.data_checks_request(
        check="inventory", subject_id=dataset.object_id,
        object_digest=dataset.digest,
        collection_digest=composition_digest(child_objects),
        evidence_ref=digest(child_evidence), policy=child_policy,
    )
    child_certificate = data_checks.build_data_checks_certificate(
        child_request, child_evidence if include_evidence else None,
        policy=child_policy,
    )
    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": [model_data_id],
        "events": ["event"], "bench": ["benchmark"],
        "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        model, dataset,
        NamespaceObject.create("architecture", "ARCH", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {
            "data": ["dataset"], "verifier": ["checker"],
        }),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {
            "arch": ["architecture"], "data": ["dataset"],
            "bench": ["benchmark"], "events": ["event"],
        }),
        NamespaceObject.create("event", "EVENT", {}, {
            "time": ["time"], "space": ["space"], "meaning": ["meaning"],
        }),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    if model_data_id != "dataset":
        objects.append(NamespaceObject.create(model_data_id, "DATA", artifact))
    evidence = canonical_bytes({
        "schema_version": citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"data_certificate_b64": base64.b64encode(child_certificate).decode("ascii")}
        if include_inputs else None,
    })
    policy = citation.model_data_policy(trust_roots=["selected-open-model-data"])
    request = citation.model_data_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(evidence), policy=policy,
        data_subject_id=dataset.object_id, data_object_digest=dataset.digest,
        data_certificate_digest=digest(child_certificate),
        data_request=child_request, data_policy=child_policy,
    )
    return request, policy, evidence


def replay(request, policy, evidence):
    certificate = citation.build_model_data_certificate(
        request, evidence, policy=policy,
    )
    return certificate, citation.recheck_model_data_certificate(
        certificate, expected_request=request, policy=policy,
    )


def test_exact_citation_replays_retained_data_inventory():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["data_inventory_prerequisite"] == "REPLAYED_LOCAL"
    assert result["actual_training_use"] == "NOT_ESTABLISHED"
    assert result["data_origin_rights"] == "NOT_ESTABLISHED"
    assert certificate == citation.build_model_data_certificate(
        request, evidence, policy=policy,
    )


def test_rehashed_false_child_inventory_does_not_become_citation():
    result = replay(*selected(
        retained_row={"id": "sample-2", "text": "other bytes"},
        declared_row={"id": "sample-1", "text": "open training sample"},
    ))[1]
    assert result["status"] == "FAIL"


def test_unknown_child_inventory_stays_unknown():
    assert replay(*selected(include_evidence=False))[1]["status"] == "UNKNOWN"


def test_child_certificate_bound_one_byte_too_small_is_unknown():
    request, policy, evidence = selected()
    child = base64.b64decode(json.loads(evidence)["inputs"]["data_certificate_b64"])
    changed = deepcopy(request)
    changed["limits"]["max_child_certificate_bytes"] = len(child) - 1
    assert replay(changed, policy, evidence)[1]["status"] == "UNKNOWN"


def test_missing_parent_inputs_stays_unknown():
    assert replay(*selected(include_inputs=False))[1]["status"] == "UNKNOWN"


def test_wrong_model_data_operand_is_refuted():
    result = replay(*selected(model_data_id="other-dataset"))[1]
    assert result["status"] == "FAIL"
    assert "MODEL data operand differs" in result["evaluation"]["details"]


def test_external_data_digest_substitution_is_refused():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["data_object_digest"] = digest(b"other dataset")
    with pytest.raises(citation.ModelDataError):
        citation.recheck_model_data_certificate(
            citation.build_model_data_certificate(request, evidence, policy=policy),
            expected_request=changed, policy=policy,
        )


def test_rehashed_forged_child_result_cannot_upgrade_false_inventory():
    request, policy, evidence = selected(
        retained_row={"id": "sample-2", "text": "other bytes"},
        declared_row={"id": "sample-1", "text": "open training sample"},
    )
    changed_evidence = json.loads(evidence)
    child = json.loads(base64.b64decode(
        changed_evidence["inputs"]["data_certificate_b64"]
    ))
    assert child["result"]["status"] == "FAIL"
    child["result"]["status"] = "PASS"
    child["digest"] = digest(canonical_bytes({
        key: value for key, value in child.items() if key != "digest"
    }))
    child_bytes = canonical_bytes(child)
    changed_evidence["inputs"]["data_certificate_b64"] = base64.b64encode(
        child_bytes
    ).decode("ascii")
    changed_bytes = canonical_bytes(changed_evidence)
    changed_request = deepcopy(request)
    changed_request["data_certificate_digest"] = digest(child_bytes)
    changed_request["evidence_ref"] = digest(changed_bytes)
    assert replay(changed_request, policy, changed_bytes)[1]["status"] == "FAIL"


def test_other_child_check_cannot_fill_inventory_prerequisite():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["data_request"]["check"] = "schema"
    with pytest.raises(citation.ModelDataError):
        citation.build_model_data_certificate(changed, evidence, policy=policy)


def test_recursive_child_selection_is_rejected_as_selection_error():
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["data_request"]["recursive"] = changed["data_request"]
    with pytest.raises(citation.ModelDataError):
        citation.build_model_data_certificate(changed, evidence, policy=policy)


def test_changed_checker_source_invalidates_selected_policy(monkeypatch):
    request, policy, evidence = selected()
    certificate = citation.build_model_data_certificate(
        request, evidence, policy=policy,
    )
    monkeypatch.setattr(citation, "mechanism_digest", lambda: digest(b"changed"))
    with pytest.raises(citation.ModelDataError):
        citation.recheck_model_data_certificate(
            certificate, expected_request=request, policy=policy,
        )


def test_rehashed_carried_result_substitution_is_rejected():
    request, policy, evidence = selected()
    certificate = json.loads(citation.build_model_data_certificate(
        request, evidence, policy=policy,
    ))
    certificate["result"]["actual_training_use"] = "ESTABLISHED"
    certificate["digest"] = digest(canonical_bytes({
        key: value for key, value in certificate.items() if key != "digest"
    }))
    with pytest.raises(citation.ModelDataError):
        citation.recheck_model_data_certificate(
            canonical_bytes(certificate), expected_request=request, policy=policy,
        )


def test_public_route_and_command_replay_exact_selected_citation(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate = citation.build_model_data_certificate(
        request, evidence, policy=policy,
    )
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=citation.SEMANTIC_VERSION,
        objective=citation.COORDINATE, represented_kind="MODEL",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["actual_training_use"] == "NOT_ESTABLISHED"
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


def test_canonical_guard_refuses_replayed_data_redaction():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    request, policy, evidence = selected()
    certificate = json.loads(citation.build_model_data_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in certificate if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)
