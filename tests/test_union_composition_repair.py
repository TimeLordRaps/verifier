from __future__ import annotations

import dataclasses
from copy import deepcopy

from verifier.runtime import core_application_authority as binding
from verifier.runtime import core_tier_progression as core_tiers
import pytest
import test_application_authority_binding as owner


def _reselect(inputs, claim, profile, authority, contributions):
    union_bytes = owner.cb(authority)
    contribution_bytes = owner.cb(contributions)
    profile["union_authority_digest"] = owner.digest(union_bytes)
    profile["union_contributions_digest"] = owner.digest(contribution_bytes)
    profile_bytes = owner.cb(profile)
    claim["authority_profile_digest"] = owner.digest(profile_bytes)
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"],
        profile_bytes=profile_bytes,
        expected_profile_digest=owner.digest(profile_bytes),
        union_authority_bytes=union_bytes,
        expected_union_authority_digest=owner.digest(union_bytes),
        union_contributions_bytes=contribution_bytes,
        expected_union_contributions_digest=owner.digest(contribution_bytes),
    )
    inputs["applicability_claim_bytes"] = owner.cb(claim)


def test_exactly_reselected_invalid_union_dependency_fails_binding():
    inputs, _, claim, profile, authority = owner.fixture()
    contributions = binding._decode_list(
        inputs["host_selection"].union_contributions_bytes, "test")
    dependency = authority["families"][0]["dependency_selection"]
    dependency["status"] = "PASS"
    dependency["producer_source_coordinate_digest"] = "sha256:" + "0" * 64
    contributions[0]["dependency_binding"] = deepcopy(dependency)
    _reselect(inputs, claim, profile, authority, contributions)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert "UNION_VALIDATION_FAILED" in report["blockers"]
    assert "UNSUPPORTED_COMPLETENESS_ASSERTION" in report["union_validation"]["issue_codes"]
    assert "DEPENDENCY_COORDINATE_MISMATCH" in report["union_validation"]["issue_codes"]


def test_reselected_missing_contribution_snapshot_fails_union_coverage():
    inputs, _, claim, profile, authority = owner.fixture()
    _reselect(inputs, claim, profile, authority, [])

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert "UNION_VALIDATION_FAILED" in report["blockers"]
    assert report["union_validation"]["candidate_coverage"] == "MISMATCH"


@pytest.mark.parametrize(("profile_field", "host_field", "observed_field", "blocker"), (
    ("application_mechanism_digest", "expected_application_mechanism_digest",
     "observed_application_mechanism_digest", "APPLICATION_MECHANISM_DIFFERS"),
    ("compiler_mechanism_digest", "expected_compiler_mechanism_digest",
     "observed_compiler_mechanism_digest", "COMPILER_MECHANISM_DIFFERS"),
    ("union_validator_digest", "expected_union_validator_digest",
     "observed_union_validator_digest", "UNION_VALIDATOR_DIFFERS"),
))
def test_self_consistent_caller_mechanism_reselection_cannot_replace_installed_source(
        profile_field, host_field, observed_field, blocker):
    inputs, _, claim, profile, authority = owner.fixture()
    fake = "sha256:" + "0" * 64
    profile[profile_field] = fake
    profile_bytes = owner.cb(profile)
    claim["authority_profile_digest"] = owner.digest(profile_bytes)
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], profile_bytes=profile_bytes,
        expected_profile_digest=owner.digest(profile_bytes), **{host_field: fake})
    inputs["applicability_claim_bytes"] = owner.cb(claim)
    inputs[observed_field] = fake

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert blocker in report["blockers"]


def test_installed_core_route_denominator_is_exact_but_not_normative_closure():
    inventory = core_tiers.installed_core_route_inventory()

    assert inventory["status"] == "PASS"
    assert inventory["family_cell_count"] == 26 * 9 == 234
    assert inventory["registered_route_membership_count"] == 408
    assert inventory["registered_route_membership_count_by_tier"] == {
        "1": 45, "2": 37, "3": 31, "4": 32, "5": 26,
        "6": 26, "7": 156, "8": 26, "9": 29,
    }
    assert len(inventory["family_cells"]) == 234
    assert all(row["denominator_status"] == "ESTABLISHED_FOR_INSTALLED_ROUTE_REGISTRY"
               and row["registered_route_memberships"]
               and row["normative_full_family_closure"] == "NOT_ESTABLISHED"
               for row in inventory["family_cells"])
    assert inventory["concrete_required_certificate_instances"] == "NOT_INSTANTIATED"
    profile = core_tiers.core_tier_profile()
    assert profile["family_cell_count"] == 234
    assert profile["registered_route_membership_count"] == 408
    assert profile["normative_full_family_closure"] == "NOT_ESTABLISHED"


def test_verifier_tier1_self_application_obligations_are_exactly_instantiated():
    family = core_tiers.verifier_tier1_self_application_obligations(
        object_id="verifier:self")

    assert family["definition_denominator_status"] == "PASS"
    assert family["definition_count"] == family["instantiated_obligation_count"] == 2
    assert [row["coordinate"] for row in family["definitions"]] == [
        "OBJECT-1.1", "VERIFIER-1.1"]
    assert {(row["object_id"], row["semantic_version"], row["coordinate"])
            for row in family["instantiated_obligations"]} == {
        ("verifier:self", "verifier-current-object-obligations-1", "OBJECT-1.1"),
        ("verifier:self", "verifier-current-object-obligations-1", "VERIFIER-1.1"),
    }
    assert family["native_instance_binding_status"] == (
        "REQUIRES_EXACT_COLLECTION_REQUEST_POLICY_AND_CERTIFICATE")


@pytest.mark.parametrize("objective", ["VERIFIER-2.999", "HUMAN-2.5"])
def test_unregistered_same_rank_objective_cannot_enter_core_progression(objective):
    from verifier.core.certificate import canonical_bytes
    import test_core_release_private as core_owner

    bundle, policy, files, selected = core_owner.selected_native()
    bundle["nodes"][0]["request"]["coordinate"] = objective
    policy["nodes"] = deepcopy(bundle["nodes"])
    selected.update(
        bundle_digest=core_tiers.digest(canonical_bytes(bundle)),
        policy_digest=core_tiers.digest(canonical_bytes(policy)),
    )

    report = core_owner.assess_native(
        bundle, policy, files, selected, cancelled=True)

    assert report["status"] == "FAIL"
    assert report["installed_route_inventory_status"] == "PASS"
    assert report["installed_route_family_cell_count"] == 234
    assert report["installed_route_membership_count"] == 408
    assert "CORE_NATIVE_OBJECTIVE_UNREGISTERED" in report["blockers"]
    assert report["native_replay"] == "NOT_RUN"
