"""Package-instance selection for retained MARKET, ROBOT, and FINBOT routes."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from test_added_kind_behavioral_mechanisms import (
    _finbot_parts,
    _market_parts,
    _robot_parts,
)
from test_manifest_gate import selected_root
from test_package_instance_evidence import prepare as prepare_current_instance
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import finbot_checks, market_checks, robot_checks
from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime import package_instance_evidence as package_evidence
from verifier.runtime import package_polish
from verifier.runtime.manifest_gate import obligation_catalog
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest
from verifier.runtime.self_polish_estate import bytes_digest


MODULES = {
    "MARKET": market_checks,
    "ROBOT": robot_checks,
    "FINBOT": finbot_checks,
}


def _retained_evidence(
        kind: str, subject_id: str, source_digest: str,
        consequence_bundle: dict | None = None) -> bytes:
    if kind == "MARKET":
        order_access, allocation, settlement = _market_parts()
        return market_checks.market_checks_evidence(
            subject_id=subject_id, source_digest=source_digest,
            order_access=order_access, matching_allocation=allocation,
            settlement_disruption=settlement,
        )
    if kind == "ROBOT":
        bundle, path, observations, hazards = _robot_parts()
        return robot_checks.robot_checks_evidence(
            subject_id=subject_id, source_digest=source_digest,
            consequence_bundle=bundle if consequence_bundle is None else consequence_bundle,
            path=path, observations=observations,
            hazards=hazards,
        )
    bundle, authority, exposures, reconciliation = _finbot_parts()
    return finbot_checks.finbot_checks_evidence(
        subject_id=subject_id, source_digest=source_digest,
        consequence_bundle=bundle if consequence_bundle is None else consequence_bundle,
        authority=authority, exposures=exposures,
        reconciliation=reconciliation,
    )


def _fixture(root, kind: str, tier: int):
    module = MODULES[kind]
    subject_id = "market" if kind == "MARKET" else "bot"
    primary = "OBJECT" if kind == "MARKET" else "BOT"
    package_bundle = None
    if kind in {"ROBOT", "FINBOT"}:
        package_bundle = deepcopy(
            _robot_parts()[0] if kind == "ROBOT" else _finbot_parts()[0]
        )
        for raw in package_bundle["rows"]:
            raw["surfaces"] = sorted({*raw["surfaces"], "file:subject.py"})
            if raw["object_id"] == subject_id:
                raw["specializations"] = sorted({*raw["specializations"], kind})
        items = tuple(
            NamespaceObject.create(
                raw["object_id"], raw["kind"], {}, raw.get("operands", {}),
            )
            for raw in package_bundle["rows"]
        )
        item = next(value for value in items if value.object_id == subject_id)
        rows = [{
            **value.to_dict(),
            "specializations": next(
                raw["specializations"] for raw in package_bundle["rows"]
                if raw["object_id"] == value.object_id
            ),
            "surfaces": next(
                raw["surfaces"] for raw in package_bundle["rows"]
                if raw["object_id"] == value.object_id
            ),
            "reason": "Retained consequence fixture object.",
            "classification": {}, "obligations": {},
        } for value in items]
    else:
        item = NamespaceObject.create(subject_id, primary, {})
        items = (item,)
        rows = [{
            **item.to_dict(), "specializations": [kind],
            "surfaces": ["file:subject.py"], "reason": "Retained fixture.",
            "classification": {}, "obligations": {},
        }]
    source = (f"def retained_{kind.lower()}_surface():\n    return None\n").encode()
    (root / "subject.py").write_bytes(source)
    source_digest = bytes_digest(source)
    retained = _retained_evidence(
        kind, subject_id, source_digest, package_bundle,
    )
    native = behavioral.routes(kind)[tier - 1]
    policy_builder = getattr(module, kind.lower() + "_checks_policy")
    request_builder = getattr(module, kind.lower() + "_checks_request")
    reference = getattr(module, kind.lower() + "_evidence_reference")
    certificate_builder = getattr(
        module, "build_" + kind.lower() + "_checks_certificate"
    )
    policy = policy_builder(trust_roots=["selected-retained-fixture"])
    request = request_builder(
        check=native.check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=reference(retained),
        policy=policy,
    )
    certificate = certificate_builder(request, retained, policy=policy)
    route = next(
        row for row in behavioral.catalog()
        if row["object_kind"] == kind and row["tier"] == tier
    )
    check = {
        "object_id": item.object_id,
        "coordinate": route["coordinate"],
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
        "reason": "This exact retained package variant selects the bounded route.",
        "evidence": [{"path": "subject.py", "sha256": source_digest}],
    }
    for name, raw in (
        ("request", canonical_bytes(request)),
        ("policy", canonical_bytes(policy)),
        ("certificate", certificate),
    ):
        path = name + ".json"
        (root / path).write_bytes(raw)
        check[name] = {"path": path, "sha256": bytes_digest(raw)}
    row = next(raw for raw in rows if raw["object_id"] == item.object_id)
    declaration = {"objects": rows, "instance_checks": [check]}
    if package_bundle is not None:
        declaration["consequence_graph"] = package_bundle["graph"]
    return item, items, row, declaration, check, route


def _replace(root, check: dict, name: str, raw: bytes) -> None:
    (root / check[name]["path"]).write_bytes(raw)
    check[name]["sha256"] = bytes_digest(raw)


def _replace_bundle(root, check: dict, kind: str, bundle: dict) -> None:
    module = MODULES[kind]
    request = json.loads((root / check["request"]["path"]).read_bytes())
    policy = json.loads((root / check["policy"]["path"]).read_bytes())
    retained = _retained_evidence(
        kind, request["subject_id"], request["source_digest"], bundle,
    )
    reference = getattr(module, kind.lower() + "_evidence_reference")
    request_builder = getattr(module, kind.lower() + "_checks_request")
    certificate_builder = getattr(
        module, "build_" + kind.lower() + "_checks_certificate"
    )
    request = request_builder(
        check=request["check"], subject_id=request["subject_id"],
        source_digest=request["source_digest"], evidence_ref=reference(retained),
        policy=policy,
    )
    _replace(root, check, "request", canonical_bytes(request))
    _replace(
        root, check, "certificate",
        certificate_builder(request, retained, policy=policy),
    )


@pytest.mark.parametrize("kind", ["MARKET", "ROBOT", "FINBOT"])
@pytest.mark.parametrize("tier", [1, 2, 3])
def test_exact_added_kind_selection_replays_through_installed_checker(
        tmp_path, kind: str, tier: int) -> None:
    item, items, row, declaration, check, route = _fixture(tmp_path, kind, tier)
    package_evidence.validate_checks(
        [check], declaration["objects"], namespace_registry(),
    )
    selected = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert selected is not None and selected["status"] == "PASS"
    assert selected["adapter_id"] == behavioral.ADAPTER
    assert selected["object_id"] == item.object_id
    assert selected["object_digest"] == item.digest
    assert selected["collection_digest"] == composition_digest(items)
    assert selected["coordinate"] == route["coordinate"]
    assert selected["obligation_id"] == route["obligation_id"]
    assert selected["semantic_version"] == route["semantic_version"]
    assert selected["proposition_digest"] == route["proposition_digest"]
    assert selected["checking_mechanism"] == route["checking_mechanism"]
    assert selected["applicability_established"] is True
    if kind in {"ROBOT", "FINBOT"}:
        selection = selected["selection"]
        assert selection["schema_version"] == "verifier-package-consequence-selection-1"
        assert selection["projection"]["object_count"] == 6
        assert selection["projection"]["edge_count"] == 3
        assert selection["projection"]["effect_count"] == 2
        assert selection["request"]["projection_digest"] == selection["projection"]["digest"]
        assert selection["certificate"]["request"] == selection["request"]
        assert selection["certificate"]["status"] == "PASS"
    assert selected["result_digest"] == value_digest({
        key: value for key, value in selected.items() if key != "result_digest"
    })


def test_added_kind_admission_requires_exact_route_and_explicit_role(tmp_path) -> None:
    _, _, row, _, check, _ = _fixture(tmp_path, "MARKET", 1)
    wrong_role = {**row, "specializations": []}
    with pytest.raises(ValueError, match="ADDED_KIND_NOT_EXPLICIT"):
        package_evidence.validate_checks(
            [check], [wrong_role], namespace_registry(),
        )
    changed = deepcopy(check)
    changed["proposition_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="PROPOSITION_DIFFERS"):
        package_evidence.validate_checks(
            [changed], [row], namespace_registry(),
        )
    changed = deepcopy(check)
    changed["coordinate"] = "MARKET-1.9"
    with pytest.raises(ValueError):
        package_evidence.validate_checks(
            [changed], [row], namespace_registry(),
        )


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("subject", "SUBJECT_OR_GRAPH_DIFFERS"),
        ("source", "ADDED_SOURCE_DIFFERS"),
        ("request_route", "REQUEST_ROUTE_DIFFERS"),
        ("policy", "certificate policy differs"),
        ("certificate", "certificate"),
        ("unowned_source", "ADDED_SOURCE_UNOWNED"),
    ],
)
def test_added_kind_wrong_bindings_fail(
        tmp_path, mutation: str, expected: str) -> None:
    item, items, row, declaration, check, route = _fixture(tmp_path, "MARKET", 1)
    request = json.loads((tmp_path / "request.json").read_bytes())
    if mutation == "subject":
        request["subject_id"] = "another-market"
        _replace(tmp_path, check, "request", canonical_bytes(request))
    elif mutation == "source":
        request["source_digest"] = "sha256:" + "9" * 64
        _replace(tmp_path, check, "request", canonical_bytes(request))
    elif mutation == "request_route":
        request["coordinate"] = "MARKET-2.1-matching-pricing-allocation"
        _replace(tmp_path, check, "request", canonical_bytes(request))
    elif mutation == "policy":
        policy = json.loads((tmp_path / "policy.json").read_bytes())
        policy["trust_roots"] = ["different-retained-selection"]
        _replace(tmp_path, check, "policy", canonical_bytes(policy))
    elif mutation == "certificate":
        value = json.loads((tmp_path / "certificate.json").read_bytes())
        value["result"]["status"] = "UNKNOWN"
        _replace(tmp_path, check, "certificate", canonical_bytes(value))
    else:
        row["surfaces"] = ["file:different.py"]
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert expected in result["reason"]


def test_missing_added_kind_bytes_remain_unknown(tmp_path) -> None:
    item, items, _, declaration, check, route = _fixture(tmp_path, "FINBOT", 3)
    (tmp_path / check["certificate"]["path"]).unlink()
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "UNKNOWN"
    assert result["replay"] is None
    assert result["applicability_established"] is False


@pytest.mark.parametrize("kind", ["ROBOT", "FINBOT"])
@pytest.mark.parametrize("mutation", ["foreign_graph", "omitted_branch", "role_swap"])
def test_consequential_certificate_cannot_substitute_a_different_package_graph(
        tmp_path, kind: str, mutation: str) -> None:
    item, items, _, declaration, check, route = _fixture(tmp_path, kind, 1)
    bundle = deepcopy(_robot_parts()[0] if kind == "ROBOT" else _finbot_parts()[0])
    for raw in bundle["rows"]:
        raw["surfaces"] = sorted({*raw["surfaces"], "file:subject.py"})
        if raw["object_id"] == item.object_id:
            raw["specializations"] = sorted({*raw["specializations"], kind})
    if mutation == "foreign_graph":
        bundle["rows"].append({
            "object_id": "foreign", "kind": "OBJECT", "specializations": [],
            "classification": {}, "surfaces": ["file:subject.py"], "operands": {},
        })
    elif mutation == "omitted_branch":
        omitted = {"ledger"} if kind == "ROBOT" else {"controller", "actuator"}
        bundle["rows"] = [
            raw for raw in bundle["rows"] if raw["object_id"] not in omitted
        ]
        bundle["graph"]["edges"] = [
            raw for raw in bundle["graph"]["edges"]
            if raw["source"] not in omitted and raw["target"] not in omitted
        ]
        bundle["graph"]["effects"] = [
            raw for raw in bundle["graph"]["effects"]
            if raw["object_id"] not in omitted
        ]
    else:
        controller = next(raw for raw in bundle["rows"] if raw["object_id"] == "controller")
        controller["specializations"] = []
    _replace_bundle(tmp_path, check, kind, bundle)
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert result["reason"] == "PACKAGE_INSTANCE_CONSEQUENCE_PROJECTION_DIFFERS"


def test_missing_package_consequence_correspondence_remains_unknown(tmp_path) -> None:
    item, items, _, declaration, check, route = _fixture(tmp_path, "FINBOT", 1)
    declaration.pop("consequence_graph")
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "UNKNOWN"
    assert result["reason"] == "PACKAGE_INSTANCE_CONSEQUENCE_GRAPH_UNAVAILABLE"
    assert result["applicability_established"] is False


def test_retained_consequence_payload_cannot_differ_from_package_object(tmp_path) -> None:
    item, items, _, declaration, check, route = _fixture(tmp_path, "ROBOT", 1)
    bundle = deepcopy(_robot_parts()[0])
    for raw in bundle["rows"]:
        raw["surfaces"] = sorted({*raw["surfaces"], "file:subject.py"})
        if raw["object_id"] == item.object_id:
            raw["specializations"] = sorted({*raw["specializations"], "ROBOT"})
    next(raw for raw in bundle["rows"] if raw["object_id"] == "controller")[
        "payload"
    ] = {"alternate": True}
    _replace_bundle(tmp_path, check, "ROBOT", bundle)
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert result["reason"] == "PACKAGE_INSTANCE_CONSEQUENCE_PROJECTION_DIFFERS"


def test_retained_operand_order_cannot_differ_from_package_identity(tmp_path) -> None:
    item, items, _, declaration, check, route = _fixture(tmp_path, "ROBOT", 1)
    ledger = next(raw for raw in declaration["objects"] if raw["object_id"] == "ledger")
    ledger["operands"] = {"refs": ["agent", "harness"]}
    package_ledger = NamespaceObject.create(
        "ledger", "OBJECT", {}, {"refs": ["agent", "harness"]},
    )
    items = tuple(
        package_ledger if value.object_id == "ledger" else value for value in items
    )
    bundle = deepcopy(_robot_parts()[0])
    for raw in bundle["rows"]:
        raw["surfaces"] = sorted({*raw["surfaces"], "file:subject.py"})
        if raw["object_id"] == item.object_id:
            raw["specializations"] = sorted({*raw["specializations"], "ROBOT"})
    next(raw for raw in bundle["rows"] if raw["object_id"] == "ledger")[
        "operands"
    ] = {"refs": ["harness", "agent"]}
    _replace_bundle(tmp_path, check, "ROBOT", bundle)
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert result["reason"] == "PACKAGE_INSTANCE_CONSEQUENCE_PROJECTION_DIFFERS"


def test_consequence_declaration_must_match_collection_denominator(tmp_path) -> None:
    item, _, _, declaration, _, route = _fixture(tmp_path, "ROBOT", 1)
    result = package_evidence.InstanceEvidence(
        tmp_path, (item,), declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "FAIL"
    assert result["reason"] == "PACKAGE_INSTANCE_CONSEQUENCE_DENOMINATOR_DIFFERS"


def test_consequence_projection_is_invariant_to_record_order(tmp_path) -> None:
    item, items, _, declaration, _, route = _fixture(tmp_path, "FINBOT", 1)
    declaration["objects"].reverse()
    declaration["consequence_graph"]["edges"].reverse()
    declaration["consequence_graph"]["effects"].reverse()
    result = package_evidence.InstanceEvidence(
        tmp_path, tuple(reversed(items)), declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "PASS"


def test_stale_package_projection_digest_is_rejected(tmp_path) -> None:
    item, items, _, declaration, _, route = _fixture(tmp_path, "ROBOT", 1)
    result = package_evidence.InstanceEvidence(
        tmp_path, items, declaration,
    ).evaluate(item, route)
    assert result is not None and result["status"] == "PASS"
    selection = result["selection"]
    certificate = deepcopy(selection["certificate"])
    certificate["request"]["projection_digest"] = "sha256:" + "0" * 64
    certificate["digest"] = value_digest({
        key: value for key, value in certificate.items() if key != "digest"
    })
    with pytest.raises(ValueError, match="PACKAGE_INSTANCE_CONSEQUENCE_REQUEST_DIFFERS"):
        package_evidence._recheck_consequence_binding(
            certificate, expected_request=selection["request"],
            native_certificate=(tmp_path / "certificate.json").read_bytes(),
            package_projection=selection["projection"],
            retained_projection=selection["projection"],
        )


def test_existing_current_object_result_is_subject_and_snapshot_bound(
        selected_root) -> None:
    document, check = prepare_current_instance(selected_root)
    objects = package_polish.tier_zero_manifest._namespace_objects(
        document["objects"]
    )
    item = next(row for row in objects if row.object_id == check["object_id"])
    route = next(
        row for row in obligation_catalog()
        if row["coordinate"] == check["coordinate"]
    )
    result = package_evidence.InstanceEvidence(
        selected_root, objects, document["namespace"],
    ).evaluate(item, route)
    assert result is not None and result["status"] == "PASS"
    assert result["object_id"] == item.object_id
    assert result["object_digest"] == item.digest
    assert result["collection_digest"] == composition_digest(objects)
    assert result["result_digest"] == value_digest({
        key: value for key, value in result.items() if key != "result_digest"
    })
