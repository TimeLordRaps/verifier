"""Refutable current SIM-3.4 external-law statement examples."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_external_law
from verifier.domains.inventory import MECHANIZED_12_POINT_BINDINGS
from verifier.runtime.public_cli import main


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _module():
    return sim_external_law


def _selected(*, statement: object = "A declared closed-system energy balance.",
              source_ref: object = "urn:example:external-law:v1",
              law_id: str = "law", linked_law_id: str = "law",
              absent_statement: bool = False, limits: dict[str, int] | None = None):
    module = _module()
    law_payload = {"schema_version": "verifier-external-law-statement-1",
                   "statement": statement,
                   "applicability": "A declared closed system with boundary fluxes accounted for.",
                   "source_ref": source_ref}
    if absent_statement:
        del law_payload["statement"]
    law = NamespaceObject.create(law_id, "OBJECT", law_payload)
    objects = [NamespaceObject.create("data", "DATA", {}),
               NamespaceObject.create("checker", "VERIFIER", {}),
               NamespaceObject.create("env", "ENV", {}), law]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-external-law-statement",
        "modelled_law_object_id": linked_law_id,
    }, {"data": ["data"], "verifier": ["checker"],
        "objects": [law_id], "env": ["env"]})
    objects.append(subject)
    evidence = {"schema_version": module.EVIDENCE_VERSION,
                "objects": [item.to_dict() for item in objects]}
    policy = module.sim_external_law_policy(trust_roots=["selected-law-fixture"])
    request = module.sim_external_law_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        law_object_id=law.object_id, law_object_digest=law.digest,
        law_statement_digest=_digest(statement if not absent_statement else "selected-statement"),
        source_ref=source_ref if isinstance(source_ref, str) else "urn:example:external-law:v1",
        evidence_ref=_digest(evidence), policy=policy, limits=limits)
    return module, request, policy, canonical_bytes(evidence)


def _replay(module, request, policy, evidence):
    certificate = module.build_sim_external_law_certificate(request, evidence,
                                                            policy=policy)
    return module.recheck_sim_external_law_certificate(
        certificate, expected_request=request, policy=policy)


def selected():
    _, request, policy, evidence = _selected()
    return request, policy, evidence


def test_native_collection_binds_distinct_law_operand():
    law = NamespaceObject.create("law", "OBJECT", {"statement": "selected"})
    sim = NamespaceObject.create("sim", "SIM", {}, {"data": ["data"],
        "verifier": ["checker"], "objects": ["law"], "env": ["env"]})
    records = [NamespaceObject.create("data", "DATA", {}),
               NamespaceObject.create("checker", "VERIFIER", {}),
               NamespaceObject.create("env", "ENV", {}), law, sim]
    result = assess_composition(records, expected_digest=composition_digest(records))
    assert result.verdict.value == "PASS"


def test_selected_external_statement_replays_without_law_truth_upgrade():
    module, request, policy, evidence = _selected()
    result = _replay(module, request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["physical_law_truth"] == "NOT_ESTABLISHED"
    assert result["external_source_authority"] == "NOT_ESTABLISHED"
    assert result["external_origin"] == "NOT_ESTABLISHED"
    assert result["sim_tier_3_conformance"] == "NOT_ESTABLISHED"


def test_absurd_selected_statement_does_not_acquire_physical_truth():
    module, request, policy, evidence = _selected(statement="Purple clocks repeal gravity.")
    result = _replay(module, request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["physical_law_truth"] == "NOT_ESTABLISHED"
    assert result["physical_applicability"] == "NOT_ESTABLISHED"


def test_reselected_different_statement_cannot_satisfy_old_law_selection():
    module, request, policy, evidence = _selected(statement="First declared law.")
    _, changed_request, _, changed_evidence = _selected(statement="Different declared law.")
    request["law_object_digest"] = changed_request["law_object_digest"]
    request["collection_digest"] = changed_request["collection_digest"]
    request["object_digest"] = changed_request["object_digest"]
    request["evidence_ref"] = _digest(json.loads(changed_evidence))
    assert _replay(module, request, policy, changed_evidence)["status"] == "FAIL"


def test_present_wrong_sim_law_relation_fails():
    module, request, policy, evidence = _selected(linked_law_id="different")
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_missing_statement_is_unknown_and_empty_statement_fails():
    module, request, policy, evidence = _selected(absent_statement=True)
    assert _replay(module, request, policy, evidence)["status"] == "UNKNOWN"
    module, request, policy, evidence = _selected(statement="")
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_missing_retained_bundle_is_unknown():
    module, request, policy, _ = _selected()
    assert _replay(module, request, policy, None)["status"] == "UNKNOWN"


def test_present_source_reference_substitution_fails():
    module, request, policy, evidence = _selected()
    changed = deepcopy(request)
    changed["source_ref"] = "urn:example:other-law:v1"
    assert _replay(module, changed, policy, evidence)["status"] == "FAIL"


def test_present_malformed_source_fails_and_selected_bounds_stop_unknown():
    module, request, policy, evidence = _selected(source_ref=42)
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"
    module, request, policy, evidence = _selected(limits={"max_objects": 4})
    assert _replay(module, request, policy, evidence)["status"] == "UNKNOWN"
    module, request, policy, evidence = _selected(limits={"max_operations": 1})
    assert _replay(module, request, policy, evidence)["status"] == "UNKNOWN"


def test_public_route_rechecks_exact_external_law_statement():
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_external_law_certificate(request, evidence,
                                                            policy=policy)
    report = routes.replay_current_object_certificate(certificate,
        semantic_version=module.SEMANTIC_VERSION, objective=module.COORDINATE,
        represented_kind="SIM", expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["physical_law_truth"] == "NOT_ESTABLISHED"


def test_public_cli_does_not_modify_selected_files(tmp_path, capsys):
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_external_law_certificate(request, evidence,
                                                            policy=policy)
    paths = [tmp_path / name for name in ("certificate.json", "request.json", "policy.json")]
    for path, data in zip(paths, (certificate, canonical_bytes(request), canonical_bytes(policy))):
        path.write_bytes(data)
    before = [path.read_bytes() for path in paths]
    assert main(["current-object", "check", str(paths[0]), "--semantic-version",
        module.SEMANTIC_VERSION, "--objective", module.COORDINATE,
        "--represented-kind", "SIM", "--request", str(paths[1]),
        "--policy", str(paths[2]), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["computational_status"] == "PASS"
    assert [path.read_bytes() for path in paths] == before


def test_rehashed_carried_verdict_cannot_replace_replay():
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_external_law_certificate(request, evidence,
                                                            policy=policy)
    changed = json.loads(certificate)
    changed["result"]["status"] = "FAIL"
    changed["digest"] = _digest({key: value for key, value in changed.items() if key != "digest"})
    with pytest.raises(module.SimExternalLawError):
        module.recheck_sim_external_law_certificate(canonical_bytes(changed),
            expected_request=request, policy=policy)


def test_inventory_binds_exact_selected_proposition():
    module = _module()
    binding = MECHANIZED_12_POINT_BINDINGS["SIM-3.4"]
    assert binding["exact_claim"] == module.registration()["proposition"]
    assert binding["resulting_evidence"] == module.CERTIFICATE_VERSION
