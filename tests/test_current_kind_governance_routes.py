"""Public exact-kind signed governance selection and bounded inventory checks.

Verifier Standard (VSTD); command-line interface (CLI); JavaScript Object
Notation (JSON). Counts are dimensionless. This is not a whole-tier certificate.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import object_governance as governance
from verifier.domains.inventory import get_slot
from verifier.runtime.polish import assess_polish
from verifier.runtime.public_cli import main
from test_current_kind_governance import KINDS, digest, encoded, specimen


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_public_route_binds_selected_governance(kind: str) -> None:
    request, policy, evidence = specimen(kind)
    certificate = governance.build_governance_certificate(request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version="verifier-current-object-obligations-1",
        objective=kind + "-8.1", represented_kind=kind,
        expected_request=request, policy=policy)
    assert result["schema_version"] == "verifier-current-object-route-replay-2"
    assert result["computational_status"] == "PASS"
    assert result["replay_status"] == "REPRODUCED"
    assert result["native_result"]["object_kind"] == kind
    assert "no legal compliance" in result["claim_boundary"]
    assert "whole governance tier" in result["claim_boundary"]
    foreign_kind = "MODEL" if kind != "MODEL" else "HUMAN"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version="verifier-current-object-obligations-1",
            objective=kind + "-8.1", represented_kind=foreign_kind,
            expected_request=request, policy=policy)


def test_catalog_and_inventory_bind_all_26_exact_governance_propositions() -> None:
    rows = [row for row in routes.current_object_route_catalog()
            if row["objective"] in {kind + "-8.1" for kind in KINDS}]
    assert len(rows) == 26
    for kind in KINDS:
        row = next(row for row in rows if row["objective"] == kind + "-8.1")
        assert row["represented_kind_rule"] == kind
        assert row["proposition_digest"] == digest(governance.registration(kind))
        assert row["scope"] == "selected_signed_namespace_admission_quorum"
        assert row["object_profile_conformance"] == "NOT_ESTABLISHED"
        slot = get_slot(kind, 8)
        assert slot.mechanized is True
        assert slot.coordinate == kind + "-8.1"
        assert slot.mechanized_route["exact_claim"] == governance.registration(kind)["proposition"]
        assert "whole governance tier" in slot.mechanized_route["assumptions_and_exclusions"]


def test_human_governance_public_command_is_read_only_and_polish_stays_unknown(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    request, policy, evidence = specimen("HUMAN")
    certificate = governance.build_governance_certificate(request, evidence, policy=policy)
    values = {"certificate": certificate, "request": encoded(request), "policy": encoded(policy)}
    paths = {name: tmp_path / (name + ".json") for name in values}
    for name, value in values.items():
        paths[name].write_bytes(value)
    code = main(["current-object", "check", str(paths["certificate"]),
        "--semantic-version", "verifier-current-object-obligations-1",
        "--objective", "HUMAN-8.1", "--represented-kind", "HUMAN",
        "--request", str(paths["request"]), "--policy", str(paths["policy"]), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    assert values == {name: path.read_bytes() for name, path in paths.items()}

    item = NamespaceObject.create("selected-subject", "HUMAN", {"declared": "value"})
    certificate_ref = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [item.to_dict()],
              "certificates": {certificate_ref: certificate.decode("utf-8")}}
    selected = {"schema_version": "verifier-polish-request-1",
        "root_id": item.object_id, "collection_digest": composition_digest([item]),
        "bundle_digest": digest(bundle), "requirements": [
            {"object_id": item.object_id, "tier": tier, "applicability": "REQUIRED",
             "rationale": "Selected signed namespace admission only", "objectives": []}
            for tier in range(1, 10)]}
    selected["requirements"][7]["objectives"] = [{
        "semantic_version": "verifier-current-object-obligations-1", "coordinate": "HUMAN-8.1",
        "request": request, "policy": policy, "certificate_digest": certificate_ref}]
    assessment = assess_polish(encoded(bundle), request_bytes=encoded(selected))
    assert assessment["objectives"][0]["status"] == "PASS"
    assert assessment["status"] == "UNKNOWN"
    assert assessment["polished"] is False

    # Keep the original signed request/certificate while selecting another
    # retained subject. Descriptor dispatch must preserve subject binding.
    foreign = NamespaceObject.create("other-subject", "HUMAN", {"declared": "value"})
    bundle["objects"] = [foreign.to_dict()]
    selected["root_id"] = foreign.object_id
    selected["collection_digest"] = composition_digest([foreign])
    selected["bundle_digest"] = digest(bundle)
    for requirement in selected["requirements"]:
        requirement["object_id"] = foreign.object_id
    refusal = assess_polish(encoded(bundle), request_bytes=encoded(selected))
    assert refusal["objectives"][0]["status"] == "FAIL"
    assert refusal["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert refusal["status"] == "FAIL"
    assert refusal["polished"] is False
