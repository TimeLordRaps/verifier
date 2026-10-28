from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from verifier.core.namespace import ObjectKind
from verifier.runtime import core_security9_accounting as accounting


def cb(value):
    return accounting.canonical_bytes(value)


def h(label: str) -> str:
    return accounting.bytes_digest(label.encode())


def source(label: str) -> dict:
    return {"uri": f"urn:security9:test:{label}", "sha256": h(label)}


def checker(label: str, *, request: str | None = None, policy: str | None = None) -> dict:
    return {"identifier": f"checker-{label}", "mechanism_digest": h(f"mechanism-{label}"),
            "request_digest": request or h(f"request-{label}"),
            "policy_digest": policy or h(f"policy-{label}")}


def falsifier(label: str) -> dict:
    return {"identifier": f"falsifier-{label}", "source": source(f"falsifier-{label}"),
            "claim_sha256": h(f"claim-{label}"), "checker_identifier": f"checker-{label}"}


def native_instance(label: str, object_id: str) -> dict:
    return {
        "instance_id": label,
        "object_id": object_id,
        "operation_id": f"operate-{label}",
        "context_digest": h(f"context-{label}"),
        "instruction_digest": h(f"instruction-{label}"),
        "generation": 3,
        "shard_id": "security-shard",
        "node_id": f"node-{label}",
        "tier": 9,
        "semantic_version": "verifier-current-object-obligations-1",
        "objective": f"{object_id}-9.1",
        "proposition_digest": h(f"proposition-{label}"),
        "request_digest": h(f"request-{label}"),
        "checker_policy_digest": h(f"policy-{label}"),
    }


def dependency(label: str) -> dict:
    return {"requirement_id": label, "required_status": "REQUIRED",
            "source": source(label), "claim_sha256": h(f"claim-{label}"),
            "checker": checker(label), "falsifiers": [falsifier(label)]}


def fixture():
    data = native_instance("security-data", "data-1")
    verifier = native_instance("security-verifier", "verifier-1")
    instances = [data, verifier]
    by_kind = {"DATA": [data["instance_id"]], "VERIFIER": [verifier["instance_id"]]}
    families = []
    selected_families = []
    for kind in ObjectKind:
        identifiers = by_kind.get(kind.value, [])
        census = "COMPLETE" if identifiers else "UNKNOWN"
        families.append({"object_kind": kind.value, "tier": 9, "tier_name": "SECURITY",
                         "census": census, "required_instances": identifiers})
        selected_families.append({**families[-1],
                                  "applicability_source": source(f"applicability-{kind.value}")})
    requirements = {
        "schema_version": accounting.CORE_REQUIREMENTS_SCHEMA,
        "profile_id": accounting.CORE_PROFILE,
        "root": {"object_id": "verifier-1"},
        "tiers": [],
        "families": families,
        "instances": instances,
        "extension": None,
    }
    child_id = "security-child-1"
    interaction_id = "security-interaction-1"
    selected_instances = []
    for row in instances:
        label = row["instance_id"]
        child_ids = [child_id] if label == data["instance_id"] else []
        selected_instances.append({
            "instance_id": label,
            "instance_binding_digest": accounting.value_digest(row),
            "threat_model": {"identifier": f"threat-{label}",
                             "source": source(f"threat-{label}"),
                             "claim_sha256": h(f"threat-claim-{label}")},
            "trusted_roots": [{"identifier": f"root-{label}", "role": "selected-policy-root",
                               "artifact_digest": h(f"root-{label}")}],
            "scope": {field: row[field] for field in (
                "object_id", "operation_id", "context_digest", "instruction_digest",
                "generation", "semantic_version", "objective", "proposition_digest")},
            "checker": checker(label, request=row["request_digest"],
                               policy=row["checker_policy_digest"]),
            "falsifiers": [falsifier(label)],
            "dependency_census": "COMPLETE",
            "child_requirement_ids": child_ids,
            "interaction_census": "COMPLETE",
            "interaction_requirement_ids": [interaction_id],
        })
    coordinate = {"source_digest": h("source-coordinate"), "version": "2.0.0"}
    requirements_bytes = cb(requirements)
    selection = {
        "schema_version": accounting.SELECTION_SCHEMA,
        "candidate_status": "CANDIDATE",
        "semantic_completeness": "UNKNOWN",
        "profile_id": accounting.CORE_PROFILE,
        "consumer_source_coordinate": deepcopy(coordinate),
        "consumer_source_coordinate_digest": accounting.value_digest(coordinate),
        "requirements_digest": accounting.bytes_digest(requirements_bytes),
        "security_requirements_spec_digest": accounting.bytes_digest(
            (Path(accounting.__file__).resolve().parents[1]
             / "standard" / "CORE_SECURITY9_REQUIREMENTS.md").read_bytes()),
        "families": selected_families,
        "instances": selected_instances,
        "child_requirements": [{"subject_instance_id": data["instance_id"],
                                "requirement": dependency(child_id)}],
        "interaction_requirements": [{"participant_instance_ids": [data["instance_id"],
                                                                     verifier["instance_id"]],
                                      "requirement": dependency(interaction_id)}],
    }
    return selection, requirements, coordinate


def assess(selection, requirements, coordinate, **overrides):
    selection_bytes = cb(selection)
    requirements_bytes = cb(requirements)
    inputs = {
        "requirements_bytes": requirements_bytes,
        "expected_selection_digest": accounting.bytes_digest(selection_bytes),
        "expected_requirements_digest": accounting.bytes_digest(requirements_bytes),
        "expected_consumer_source_coordinate": coordinate,
        "expected_consumer_source_coordinate_digest": accounting.value_digest(coordinate),
        "expected_mechanism_digest": accounting.mechanism_digest(),
    }
    inputs.update(overrides)
    return accounting.assess_security9_accounting(selection_bytes, **inputs)


def test_exact_structural_accounting_passes_without_granting_semantic_or_release_credit():
    selection, requirements, coordinate = fixture()
    report = assess(selection, requirements, coordinate)

    assert report["status"] == "UNKNOWN"
    assert report["structural_status"] == "PASS"
    assert report["family_accounting"] == "PASS"
    assert report["checker_accounting"] == "PASS"
    assert report["falsifier_accounting"] == "PASS"
    assert report["interaction_accounting"] == "PASS"
    assert report["selected_family_count"] == 26
    assert report["selected_instance_count"] == 2
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["public_checkability"] == "UNKNOWN"
    assert report["human_acceptance"] == "UNKNOWN"
    assert report["release_admissible"] is False
    assert "SECURITY9_APPLICABILITY_UNKNOWN" in report["blockers"]
    assert "SECURITY9_SEMANTIC_COMPLETENESS_UNKNOWN" in report["blockers"]


@pytest.mark.parametrize(("mutation", "blocker"), [
    (lambda selection: selection["families"].pop(), "SECURITY9_FAMILY_SET_DIFFERS"),
    (lambda selection: selection["families"][0].update(tier=6), "SECURITY9_FAMILY_FIELDS"),
    (lambda selection: selection.update(semantic_completeness="COMPLETE"),
     "SECURITY9_SELECTION_VERSION"),
    (lambda selection: selection["instances"][0]["checker"].update(
        request_digest=h("substituted-request")), "SECURITY9_CHECKER_BINDING_DIFFERS"),
    (lambda selection: selection["instances"][0].update(falsifiers=[]),
     "SECURITY9_FALSIFIER_REQUIRED"),
    (lambda selection: selection["instances"][0]["falsifiers"][0].update(
        checker_identifier="unselected-checker"), "SECURITY9_FALSIFIER_CHECKER_DIFFERS"),
    (lambda selection: selection["instances"][0].update(interaction_requirement_ids=[]),
     "SECURITY9_INTERACTION_BINDING_DIFFERS"),
])
def test_adversarial_substitution_and_omission_are_failures(mutation, blocker):
    selection, requirements, coordinate = fixture()
    mutation(selection)
    report = assess(selection, requirements, coordinate)
    assert report["status"] == "FAIL"
    assert report["structural_status"] == "FAIL"
    assert blocker in report["blockers"]
    assert report["release_admissible"] is False


def test_consumer_source_substitution_is_refused_against_host_pin():
    selection, requirements, coordinate = fixture()
    selection["consumer_source_coordinate"]["version"] = "substituted"
    selection["consumer_source_coordinate_digest"] = accounting.value_digest(
        selection["consumer_source_coordinate"])
    report = assess(selection, requirements, coordinate)
    assert report["status"] == "FAIL"
    assert "SECURITY9_SOURCE_COORDINATE_DIFFERS" in report["blockers"]


def test_requirements_instance_omission_cannot_be_hidden_by_rebinding_selection():
    selection, requirements, coordinate = fixture()
    removed = requirements["instances"].pop()
    family = next(row for row in requirements["families"]
                  if row["object_kind"] == "VERIFIER" and row["tier"] == 9)
    family.update(census="UNKNOWN", required_instances=[])
    requirements_bytes = cb(requirements)
    selection["requirements_digest"] = accounting.bytes_digest(requirements_bytes)
    report = assess(selection, requirements, coordinate)
    assert removed["instance_id"] == "security-verifier"
    assert report["status"] == "FAIL"
    assert "SECURITY9_FAMILY_BINDING_DIFFERS" in report["blockers"]


def test_unknown_dependency_and_interaction_censuses_remain_explicit_blockers():
    selection, requirements, coordinate = fixture()
    selection["instances"][0]["dependency_census"] = "UNKNOWN"
    selection["instances"][1]["interaction_census"] = "UNKNOWN"
    report = assess(selection, requirements, coordinate)
    assert report["structural_status"] == "PASS"
    assert "SECURITY9_DEPENDENCY_CENSUS_UNKNOWN" in report["blockers"]
    assert "SECURITY9_INTERACTION_CENSUS_UNKNOWN" in report["blockers"]
    assert report["status"] == "UNKNOWN"


@pytest.mark.parametrize(("collection", "blocker"), [
    ("child_requirements", "SECURITY9_DEPENDENCY_CENSUS_UNKNOWN"),
    ("interaction_requirements", "SECURITY9_INTERACTION_CENSUS_UNKNOWN"),
])
def test_unknown_requirement_status_cannot_hide_behind_complete_census(collection, blocker):
    selection, requirements, coordinate = fixture()
    selection[collection][0]["requirement"]["required_status"] = "UNKNOWN"

    report = assess(selection, requirements, coordinate)

    assert report["structural_status"] == "PASS"
    assert blocker in report["blockers"]
    assert report["status"] == "UNKNOWN"


def test_cancellation_is_unknown_and_grants_no_structural_credit():
    selection, requirements, coordinate = fixture()
    report = assess(selection, requirements, coordinate, cancelled=True)
    assert report["status"] == "UNKNOWN"
    assert report["structural_status"] == "UNKNOWN"
    assert {"SECURITY9_ACCOUNTING_CANCELLED", "SECURITY9_ACCOUNTING_NOT_RUN"} <= set(
        report["blockers"])
    assert report["release_admissible"] is False


def test_capacity_exhaustion_is_unknown_not_a_pass_or_refutation():
    _, requirements, coordinate = fixture()
    oversized = b"x" * (accounting.MAX_RECORD_BYTES + 1)
    report = accounting.assess_security9_accounting(
        oversized,
        requirements_bytes=cb(requirements),
        expected_selection_digest=h("oversized-selection"),
        expected_requirements_digest=accounting.bytes_digest(cb(requirements)),
        expected_consumer_source_coordinate=coordinate,
        expected_consumer_source_coordinate_digest=accounting.value_digest(coordinate),
        expected_mechanism_digest=accounting.mechanism_digest(),
    )
    assert report["status"] == "UNKNOWN"
    assert report["structural_status"] == "UNKNOWN"
    assert "SECURITY9_ACCOUNTING_CAPACITY_EXHAUSTED" in report["blockers"]


def test_assessment_digest_recomputes_exact_report_body():
    selection, requirements, coordinate = fixture()
    report = assess(selection, requirements, coordinate)
    body = {key: value for key, value in report.items() if key != "assessment_digest"}
    assert report["assessment_digest"] == accounting.value_digest(body)


def test_security9_mechanism_binds_installed_route_inventory_source(
        monkeypatch: pytest.MonkeyPatch):
    before = accounting.mechanism_digest()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\ninstalled-route-substitution" if path.name == "inventory.py" else raw

    monkeypatch.setattr(Path, "read_bytes", changed)

    assert accounting.mechanism_digest() != before


def test_core_release_consumes_exact_accounting_without_converting_unknown_to_pass():
    from verifier.runtime import core_application_release as release
    import test_core_release_private as owner

    data = owner.application_input()
    requirements_bytes = cb(data["requirements"])
    coordinate = {"source_digest": h("release-source"), "version": "2.0.0"}
    selection = {
        "schema_version": accounting.SELECTION_SCHEMA,
        "candidate_status": "CANDIDATE",
        "semantic_completeness": "UNKNOWN",
        "profile_id": accounting.CORE_PROFILE,
        "consumer_source_coordinate": deepcopy(coordinate),
        "consumer_source_coordinate_digest": accounting.value_digest(coordinate),
        "requirements_digest": accounting.bytes_digest(requirements_bytes),
        "security_requirements_spec_digest": accounting.bytes_digest(
            (Path(accounting.__file__).resolve().parents[1]
             / "standard" / "CORE_SECURITY9_REQUIREMENTS.md").read_bytes()),
        "families": [{**deepcopy(row),
                      "applicability_source": source(f"release-{row['object_kind']}")}
                     for row in data["requirements"]["families"] if row["tier"] == 9],
        "instances": [],
        "child_requirements": [],
        "interaction_requirements": [],
    }
    selection_bytes = cb(selection)
    report = owner.assess_application(
        data,
        security9_accounting_bytes=selection_bytes,
        expected_security9_accounting_digest=accounting.bytes_digest(selection_bytes),
        expected_security9_consumer_source_coordinate=coordinate,
        expected_security9_consumer_source_coordinate_digest=accounting.value_digest(coordinate),
        expected_security9_mechanism_digest=accounting.mechanism_digest(),
    )
    security = report["security9_accounting_assessment"]
    assert security["structural_status"] == "PASS"
    assert security["semantic_completeness"] == "UNKNOWN"
    assert security["release_admissible"] is False
    assert report["status"] == "UNKNOWN"
    assert report["release_authorized"] is False
    assert "APPLICATION_SECURITY9_SEMANTIC_COMPLETENESS_UNKNOWN" in report["blockers"]
    assert release.mechanism_digest() == report["expected_mechanism_digest"]


def test_core_release_reports_missing_security9_accounting_as_a_blocker():
    import test_core_release_private as owner

    report = owner.assess_application(owner.application_input())
    assert report["security9_accounting_assessment"] is None
    assert "APPLICATION_SECURITY9_ACCOUNTING_MISSING" in report["blockers"]
    assert report["status"] == "UNKNOWN"
    assert report["release_authorized"] is False
