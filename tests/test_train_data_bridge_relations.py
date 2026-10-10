"""Challenge retained batch relations independently of valid child verdicts.

TRAIN denotes a training run specification; DATA denotes dataset integrity and
lineage. JavaScript Object Notation (JSON) serializes the retained specimens.
Counts and operation budgets are dimensionless. No historical execution claim.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import data_checks, train_data_bridge as bridge
from test_current_train_data_bridge import digest, digest_bytes, selection


def selected_views(mode: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    _, request, policy, raw = selection()
    parent = json.loads(raw)
    child = json.loads(base64.b64decode(parent["data_certificate_b64"]))
    evidence = json.loads(base64.b64decode(child["evidence_payloads"][request["data_request"]["evidence_ref"]]))
    row = evidence["inputs"]["shards"]["training"][0]
    shards = {"training": [row]}
    selected = ["training"]
    if mode in {"unselected", "other"}:
        shards["other"] = [[[{"input": [1], "target": [99]}]]]
        if mode == "other":
            selected = ["other"]
    elif mode == "duplicate":
        shards["duplicate"] = [deepcopy(row)]
        selected = ["duplicate", "training"]
    elif mode == "missing":
        selected = ["absent"]
    commitments = {
        key: {"digest": digest(rows), "records": 1,
              "bytes": len(canonical_bytes(rows)),
              "record_digests": [digest(rows[0])], "merkle_root": digest(rows[0])}
        for key, rows in shards.items()
    }
    data = NamespaceObject.create("retained-shard-view", "DATA", {"shards": commitments})
    evidence_raw = canonical_bytes({"schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [data.to_dict()], "inputs": {"shards": shards}})
    child_policy = request["data_policy"]
    child_request = data_checks.data_checks_request(
        check="inventory", subject_id=data.object_id, object_digest=data.digest,
        collection_digest=composition_digest([data]), evidence_ref=digest_bytes(evidence_raw),
        policy=child_policy)
    certificate = data_checks.build_data_checks_certificate(child_request, evidence_raw, policy=child_policy)
    assert data_checks.recheck_data_checks_certificate(
        certificate, expected_request=child_request, policy=child_policy)["status"] == "PASS"
    parent["data_certificate_b64"] = base64.b64encode(certificate).decode("ascii")
    parent_raw = canonical_bytes(parent)
    request.update(data_request=child_request, data_certificate_digest=digest_bytes(certificate),
                   evidence_ref=digest_bytes(parent_raw), shard_ids=selected)
    return request, policy, parent_raw


def verdict(request: dict[str, Any], policy: dict[str, Any], evidence: bytes) -> str:
    certificate = bridge.build_train_data_bridge_certificate(request, evidence, policy=policy)
    return bridge.recheck_train_data_bridge_certificate(
        certificate, expected_request=request, policy=policy)["status"]


@pytest.mark.parametrize("mode,expected", [
    ("selected", "PASS"), ("unselected", "PASS"), ("other", "FAIL"),
    ("duplicate", "FAIL"), ("missing", "FAIL"),
])
def test_valid_children_do_not_override_exact_selected_relation(mode: str, expected: str) -> None:
    assert verdict(*selected_views(mode)) == expected


def test_exact_parent_operation_threshold_preserves_unknown() -> None:
    request, policy, evidence = selected_views("selected")
    def outcome(limit: int) -> str:
        selected = deepcopy(request)
        selected["limits"]["max_operations"] = limit
        return verdict(selected, policy, evidence)
    low, high = 1, request["limits"]["max_operations"]
    assert outcome(low) == "UNKNOWN" and outcome(high) == "PASS"
    while high - low > 1:
        middle = (low + high) // 2
        result = outcome(middle)
        assert result in {"PASS", "UNKNOWN"}
        if result == "PASS":
            high = middle
        else:
            low = middle
    assert outcome(high) == "PASS" and outcome(high - 1) == "UNKNOWN"


def test_valid_children_cannot_supply_an_unselected_batch_view() -> None:
    request, policy, evidence = selected_views("selected")
    request["batch_view_id"] = "other-batch-view"
    assert verdict(request, policy, evidence) == "FAIL"
