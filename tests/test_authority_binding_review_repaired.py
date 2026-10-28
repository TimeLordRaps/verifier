"""Independent adversarial controls for the private authority-binding candidate."""

from __future__ import annotations

import copy
import dataclasses

from verifier.runtime import core_application_authority as binding
from verifier.runtime import core_obligation_union as union_validator
import test_application_authority_binding as owner


FAKE_DIGEST = "sha256:" + "f" * 64


def _reselect_union(inputs, claim, profile, authority):
    """Model a host independently selecting the exact mutated candidate bytes."""
    contributions = binding._decode_list(
        inputs["host_selection"].union_contributions_bytes, "review")
    if len(authority["families"]) == len(contributions):
        by_family = {row["family_id"]: row for row in contributions}
        for family in authority["families"]:
            if family["family_id"] in by_family:
                by_family[family["family_id"]]["dependency_binding"] = copy.deepcopy(
                    family["dependency_selection"])
    union_bytes = owner.cb(authority)
    contribution_bytes = owner.cb(contributions)
    profile["union_authority_digest"] = owner.digest(union_bytes)
    profile["union_contributions_digest"] = owner.digest(contribution_bytes)
    profile_bytes = owner.cb(profile)
    claim["authority_profile_digest"] = owner.digest(profile_bytes)
    host = dataclasses.replace(
        inputs["host_selection"],
        profile_bytes=profile_bytes,
        expected_profile_digest=owner.digest(profile_bytes),
        union_authority_bytes=union_bytes,
        expected_union_authority_digest=owner.digest(union_bytes),
        union_contributions_bytes=contribution_bytes,
        expected_union_contributions_digest=owner.digest(contribution_bytes),
    )
    inputs["host_selection"] = host
    inputs["applicability_claim_bytes"] = owner.cb(claim)


def test_binding_rejects_union_that_the_shipped_union_validator_rejects():
    inputs, _, claim, profile, authority = owner.fixture()
    dependency = authority["families"][0]["dependency_selection"]

    # The owner's nominal positive fixture already carries a producer-coordinate
    # digest that does not bind its producer coordinate.  Make the invalidity
    # still more explicit while preserving exact host byte selection.
    dependency["status"] = "PASS"
    dependency["producer_source_coordinate_digest"] = "sha256:" + "0" * 64
    _reselect_union(inputs, claim, profile, authority)

    report = binding.assess_application_authority_binding(**inputs)
    contributions = binding._decode_list(
        inputs["host_selection"].union_contributions_bytes, "review")
    union_report = union_validator.validate_union(
        authority,
        contributions,
        expected_authority_digest=binding.value_digest(authority),
        expected_source_coordinate=profile["consumer_source_coordinate"],
    )
    union_codes = {issue["code"] for issue in union_report["issues"]}

    assert report["binding_status"] == "FAIL"
    assert report["status"] == "FAIL"
    assert "UNION_VALIDATION_FAILED" in report["blockers"]
    assert "UNSUPPORTED_COMPLETENESS_ASSERTION" in report["union_validation"]["issue_codes"]
    assert "DEPENDENCY_COORDINATE_MISMATCH" in report["union_validation"]["issue_codes"]
    assert "UNSUPPORTED_COMPLETENESS_ASSERTION" in union_codes
    assert "DEPENDENCY_COORDINATE_MISMATCH" in union_codes
    assert union_report["structural_union"] == "FAIL"


def test_no_inapplicability_rejects_self_rebound_member_waiver():
    inputs, requirements, claim, profile, authority = owner.fixture()
    requirements = copy.deepcopy(requirements)
    profile = copy.deepcopy(profile)
    claim = copy.deepcopy(claim)
    authority = copy.deepcopy(authority)
    profile["member_requirements"][1]["applicability"] = "NOT_APPLICABLE"
    profile["member_requirements"][1]["inapplicability_basis_digest"] = (
        "sha256:" + "6" * 64
    )
    waived_id = profile["instance_requirements"][1]["instance_id"]
    profile["instance_requirements"].pop(1)
    requirements["instances"].pop(1)
    for row in profile["family_requirements"]:
        if waived_id in row["required_instances"]:
            row["required_instances"].remove(waived_id)
    for section in (requirements["families"], requirements["tiers"]):
        for row in section:
            if waived_id in row["required_instances"]:
                row["required_instances"].remove(waived_id)
    claim["member_decisions"][1]["applicability"] = "NOT_APPLICABLE"
    inputs["requirements_bytes"] = owner.cb(requirements)
    claim["requirements_digest"] = owner.digest(inputs["requirements_bytes"])
    _reselect_union(inputs, claim, profile, authority)

    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "FAIL"
    assert "UNAUTHORIZED_NOT_APPLICABLE" in report["blockers"]


def test_unknown_children_do_not_upgrade_bounded_binding_pass():
    inputs, *_ = owner.fixture()
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "PASS"
    assert report["child_status"] == "UNKNOWN"
    assert report["interaction_status"] == "UNKNOWN"
    assert report["authority_status"] == "UNKNOWN"
    assert report["full_application_status"] == "UNKNOWN"
    assert report["polished"] is False
    assert report["release_authorized"] is False


def test_all_semantic_collections_are_order_insensitive():
    inputs, requirements, claim, profile, authority = owner.fixture()
    for rows in (
        profile["member_requirements"],
        profile["instance_requirements"],
        profile["family_requirements"],
        authority["families"],
        authority["families"][0]["requirements"],
        requirements["instances"],
        requirements["families"],
        requirements["tiers"],
        claim["family_decisions"],
        claim["member_decisions"],
    ):
        rows.reverse()
    for row in profile["family_requirements"]:
        row["required_instances"].reverse()
    for section in (requirements["families"], requirements["tiers"]):
        for row in section:
            row["required_instances"].reverse()
    inputs["requirements_bytes"] = owner.cb(requirements)
    claim["requirements_digest"] = owner.digest(inputs["requirements_bytes"])
    _reselect_union(inputs, claim, profile, authority)

    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "PASS"
    assert report["status"] == "UNKNOWN"


def test_core_tier_omission_and_family_decision_duplication_fail():
    inputs, requirements, claim, *_ = owner.fixture()
    requirements["tiers"].pop()
    inputs["requirements_bytes"] = owner.cb(requirements)
    claim["requirements_digest"] = owner.digest(inputs["requirements_bytes"])
    inputs["applicability_claim_bytes"] = owner.cb(claim)
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "FAIL"
    assert "CORE_TIER_SET_DIFFERS" in report["blockers"]

    inputs, _, claim, *_ = owner.fixture()
    claim["family_decisions"].append(copy.deepcopy(claim["family_decisions"][0]))
    inputs["applicability_claim_bytes"] = owner.cb(claim)
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "FAIL"
    assert "DUPLICATE_FAMILY_DECISION" in report["blockers"]


def test_host_source_coordinate_substitution_fails():
    inputs, *_ = owner.fixture()
    foreign = copy.deepcopy(owner.coordinate())
    foreign["commit"] = "f" * 40
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"],
        expected_consumer_source_coordinate=foreign,
        expected_consumer_source_coordinate_digest=binding.value_digest(foreign),
    )
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "FAIL"
    assert "CONSUMER_SOURCE_COORDINATE_DIFFERS" in report["blockers"]


def test_each_observed_mechanism_substitution_fails():
    for field, blocker in (
        ("observed_application_mechanism_digest", "APPLICATION_MECHANISM_DIFFERS"),
        ("observed_compiler_mechanism_digest", "COMPILER_MECHANISM_DIFFERS"),
        ("observed_union_validator_digest", "UNION_VALIDATOR_DIFFERS"),
    ):
        inputs, *_ = owner.fixture()
        inputs[field] = FAKE_DIGEST
        report = binding.assess_application_authority_binding(**inputs)
        assert report["binding_status"] == "FAIL"
        assert blocker in report["blockers"]


def test_self_consistent_compiler_subject_operation_substitution_fails():
    inputs, _, claim, profile, authority = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    subject = compiler["scope_admission"]["subject"]
    subject["operation"] = "FOREIGN_SCOPE_OPERATION"
    compiler["scope_admission"]["admission_subject_digest"] = binding.value_digest(subject)
    inputs["compiler_manifest_bytes"] = owner.cb(compiler)
    profile["compiler_manifest_digest"] = owner.digest(inputs["compiler_manifest_bytes"])
    profile["scope_admission_subject_digest"] = binding.value_digest(subject)
    _reselect_union(inputs, claim, profile, authority)

    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "FAIL"
    assert "SCOPE_ADMISSION_SUBJECT_DIFFERS" in report["blockers"]


def test_opaque_scope_receipt_cannot_upgrade_authority():
    inputs, *_ = owner.fixture(not_applicable=True)
    receipt = b"opaque candidate-carried approval"
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"],
        scope_admission_receipt_bytes=receipt,
        expected_scope_admission_receipt_digest=binding.bytes_digest(receipt),
    )
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert report["authority_status"] == "UNKNOWN"
    assert "QUALIFIED_SCOPE_ADMISSION_RECEIPT_REPLAY_UNAVAILABLE" in report["blockers"]
