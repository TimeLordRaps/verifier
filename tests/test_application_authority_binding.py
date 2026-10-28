from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.runtime import core_application_authority as binding


KINDS = [
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS", "AGENT",
    "SIM", "BOT", "TOKEN",
]
ZERO = "sha256:" + "0" * 64


def cb(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def coordinate():
    return {
        "repository": "urn:verifier:test-source:v2-reconciled",
        "head": "cdfd2cf3702eaba0c40c83970826a95ea68173f2",
        "dirty_status_digest": "sha256:" + "1" * 64,
    }


def instance(number, objective, proposition):
    return {
        "instance_id": f"agent-instance-{number}",
        "object_id": "agent-1",
        "operation_id": "evaluate-agent",
        "context_digest": "sha256:" + str(number) * 64,
        "instruction_digest": "sha256:" + str(number + 2) * 64,
        "generation": 4,
        "shard_id": "agent-shard",
        "node_id": f"agent-node-{number}",
        "tier": 1,
        "semantic_version": "verifier-current-object-obligations-1",
        "objective": objective,
        "proposition_digest": proposition,
        "request_digest": "sha256:" + str(number + 4) * 64,
        "checker_policy_digest": "sha256:" + str(number + 6) * 64,
    }


def fixture(*, not_applicable=False):
    app_mechanism = binding.installed_application_mechanism_digest()
    compiler_mechanism = binding.installed_compiler_mechanism_digest()
    union_mechanism = binding.installed_union_validator_digest()
    root = {"object_id": "root", "object_kind": "VERIFIER", "record_digest": "sha256:" + "d" * 64}
    source = {"uri": "src/verifier/standard/CURRENT_TYPED_FACETS.md", "sha256": "sha256:" + "e" * 64}
    members = [
        {
            "family_id": "VERIFIER_CURRENT_OBJECT:AGENT", "object_kind": "AGENT", "tier": 1,
            "member_id": "AGENT-1.1", "semantic_version": "verifier-current-object-obligations-1",
            "objective": "AGENT-1.1", "proposition_digest": "sha256:" + "2" * 64,
            "source": source, "claim_sha256": "sha256:" + "3" * 64,
            "applicability": "REQUIRED", "inapplicability_basis_digest": None,
        },
        {
            "family_id": "VERIFIER_CURRENT_OBJECT:AGENT", "object_kind": "AGENT", "tier": 1,
            "member_id": "AGENT-1.8", "semantic_version": "verifier-current-object-obligations-1",
            "objective": "AGENT-1.8", "proposition_digest": "sha256:" + "4" * 64,
            "source": source, "claim_sha256": "sha256:" + "5" * 64,
            "applicability": "NOT_APPLICABLE" if not_applicable else "REQUIRED",
            "inapplicability_basis_digest": "sha256:" + "6" * 64 if not_applicable else None,
        },
    ]
    core_instances = [instance(1, "AGENT-1.1", members[0]["proposition_digest"])]
    if not not_applicable:
        core_instances.append(instance(2, "AGENT-1.8", members[1]["proposition_digest"]))
    expected_instances = []
    for row, member in zip(core_instances, [item for item in members if item["applicability"] == "REQUIRED"]):
        expected_instances.append({"object_kind": "AGENT", "member_id": member["member_id"], **row})

    family_requirements = []
    carried_families = []
    family_decisions = []
    for kind in KINDS:
        for tier in range(1, 10):
            required = kind == "AGENT" and tier == 1
            applicability = "REQUIRED" if required else "UNKNOWN"
            ids = [row["instance_id"] for row in core_instances] if required else []
            family_requirements.append({"object_kind": kind, "tier": tier,
                "applicability": applicability, "required_instances": ids,
                "inapplicability_basis_digest": None})
            carried_families.append({"object_kind": kind, "tier": tier,
                "tier_name": binding.TIER_NAMES[tier], "census": "COMPLETE" if required else "UNKNOWN",
                "required_instances": ids})
            family_decisions.append({"object_kind": kind, "tier": tier, "applicability": applicability})

    tiers = []
    for tier in range(1, 10):
        ids = [row["instance_id"] for row in core_instances if row["tier"] == tier]
        tiers.append({"tier": tier, "tier_name": binding.TIER_NAMES[tier],
            "census": "COMPLETE" if ids else "UNKNOWN", "required_instances": ids})

    requirements = {
        "schema_version": binding.CORE_REQUIREMENTS_SCHEMA,
        "profile_id": binding.CORE_PROFILE,
        "root": root,
        "tiers": tiers,
        "families": carried_families,
        "instances": core_instances,
        "extension": {"schema_version": binding.CORRIGIBILITY_EXTENSION,
            "profile_id": binding.CORRIGIBILITY_EXTENSION, "declared_status": "WIP",
            "binding_digest": "sha256:" + "7" * 64},
    }

    producer_coordinate = {"source": "selected-family-matrix", "sha256": "sha256:" + "9" * 64}
    dependency_selection = {"status": "UNKNOWN",
        "producer_source_coordinate_digest": binding.value_digest(producer_coordinate),
        "consumer_source_coordinate_digest": binding.value_digest(coordinate()),
        "candidate_input_digest": "sha256:" + "b" * 64,
        "package_digest": "sha256:" + "c" * 64,
        "mechanism_digest": "sha256:" + "d" * 64}
    union_authority = {
        "schema_version": binding.UNION_AUTHORITY_SCHEMA,
        "candidate_status": "CANDIDATE", "completeness": "UNKNOWN",
        "consumer_source_coordinate": coordinate(),
        "families": [{
            "family_id": "VERIFIER_CURRENT_OBJECT:AGENT", "source_map_digest": "sha256:" + "8" * 64,
            "producer_source_coordinate": producer_coordinate,
            "dependency_selection": dependency_selection,
            "requirements": [{"object_kind": row["object_kind"], "tier": row["tier"],
                "member_id": row["member_id"], "source": row["source"],
                "claim_sha256": row["claim_sha256"]} for row in members],
        }],
    }
    union_bytes = cb(union_authority)
    union_contributions = [{
        "schema_version": "verifier-core-obligation-contribution-candidate-1",
        "candidate_status": "CANDIDATE", "completeness": "UNKNOWN",
        "producer_source_coordinate": producer_coordinate,
        "consumer_source_coordinate": coordinate(),
        "family_id": "VERIFIER_CURRENT_OBJECT:AGENT",
        "source_map_digest": "sha256:" + "8" * 64,
        "dependency_binding": dependency_selection,
        "rows": [{
            "source": row["source"],
            "claim": {"text": f"Exact selected claim for {row['member_id']}",
                      "sha256": binding.text_digest(f"Exact selected claim for {row['member_id']}")},
            "object_kind": row["object_kind"], "tier": row["tier"],
            "member_id": row["member_id"],
            "acceptance_mechanism": {"kind": "REGISTERED", "identifier": row["objective"]},
            "current_evidence": {"status": "UNKNOWN", "bindings": []},
            "uncovered_action": "Replay the exact selected instance and preserve UNKNOWN until qualified.",
        } for row in members],
    }]
    # Union authority claim digests must bind the exact contribution claim text.
    for requirement, row in zip(union_authority["families"][0]["requirements"],
                                union_contributions[0]["rows"]):
        requirement["claim_sha256"] = row["claim"]["sha256"]
    for member, row in zip(members, union_contributions[0]["rows"]):
        member["claim_sha256"] = row["claim"]["sha256"]
    union_bytes = cb(union_authority)
    union_contributions_bytes = cb(union_contributions)
    input_digests = {
        "source_scope": "sha256:" + "f" * 64,
        "collection": "sha256:" + "1" * 64,
        "selection": "sha256:" + "2" * 64,
        "compiler_policy": "sha256:" + "3" * 64,
    }
    closure = {
        "schema_version": "verifier-application-census-closure-1",
        "scope_kind": "full-current-application-1",
        "source_scope_digest": input_digests["source_scope"],
        "input_digests": input_digests,
        "mechanism_digest": compiler_mechanism,
        "member_set_digests": {
            name: "sha256:" + "4" * 64 for name in binding.COMPILER_MEMBER_SET_NAMES},
        "conservation_status": "UNKNOWN",
        "complete_bounds": True,
        "full_application_status": "UNKNOWN",
        "claim_boundary": "Bounded fixture; full application remains UNKNOWN.",
    }
    closure["digest"] = binding.value_digest(closure)
    subject = {
        "schema_version": "verifier-application-scope-admission-subject-1",
        "operation": "ADMIT_APPLICATION_REQUIREMENT_SCOPE",
        "scope_kind": "full-current-application-1",
        "closure_certificate_digest": closure["digest"],
        "input_digests": input_digests,
        "mechanism_digest": compiler_mechanism,
        "admitted_inapplicability": [],
    }
    compiler_manifest = {
        "schema_version": "verifier-current-application-obligations-1",
        "mechanism_digest": compiler_mechanism,
        "full_application_status": "UNKNOWN",
        "interaction_census_status": "UNKNOWN",
        "consumer_census_status": "UNKNOWN",
        "native_projection_status": "UNKNOWN",
        "input_digests": input_digests,
        "scope_kind": "full-current-application-1",
        "closure_certificate": closure,
        "scope_admission": {"authority_status": "NOT_EVALUATED", "subject": subject,
            "admission_subject_digest": binding.value_digest(subject)},
    }
    compiler_bytes = cb(compiler_manifest)
    profile = {
        "schema_version": binding.AUTHORITY_PROFILE_SCHEMA,
        "profile_id": "tyler-selected-v2-core-application",
        "profile_version": "2026-10-08.1",
        "core_profile_id": binding.CORE_PROFILE,
        "root": root,
        "consumer_source_coordinate": coordinate(),
        "consumer_source_coordinate_digest": binding.value_digest(coordinate()),
        "application_mechanism_digest": app_mechanism,
        "compiler_mechanism_digest": compiler_mechanism,
        "union_validator_digest": union_mechanism,
        "union_authority_digest": digest(union_bytes),
        "union_contributions_digest": digest(union_contributions_bytes),
        "compiler_manifest_digest": digest(compiler_bytes),
        "scope_admission_subject_digest": binding.value_digest(subject),
        "receipt_mode": "QUALIFIED_SCOPE_ADMISSION_REQUIRED" if not_applicable else "NO_INAPPLICABILITY",
        "family_requirements": family_requirements,
        "member_requirements": members,
        "instance_requirements": expected_instances,
        "child_requirements": [{"requirement_id": "native-agent-child", "required_status": "REQUIRED"}],
        "interaction_requirements": [{"requirement_id": "agent-harness-interaction", "required_status": "REQUIRED"}],
        "corrigibility_extension_status": "WIP",
    }
    profile_bytes = cb(profile)
    claim = {
        "schema_version": binding.APPLICABILITY_CLAIM_SCHEMA,
        "authority_profile_digest": digest(profile_bytes),
        "requirements_digest": digest(cb(requirements)),
        "family_decisions": family_decisions,
        "member_decisions": [{"object_kind": row["object_kind"], "tier": row["tier"],
            "member_id": row["member_id"], "applicability": row["applicability"]} for row in members],
        "child_outcomes": [{"requirement_id": "native-agent-child", "status": "UNKNOWN", "evidence_digest": None}],
        "interaction_outcomes": [{"requirement_id": "agent-harness-interaction", "status": "UNKNOWN", "evidence_digest": None}],
    }
    host = binding.ApplicationAuthorityHostSelection(
        profile_bytes=profile_bytes,
        expected_profile_digest=digest(profile_bytes),
        union_authority_bytes=union_bytes,
        expected_union_authority_digest=digest(union_bytes),
        union_contributions_bytes=union_contributions_bytes,
        expected_union_contributions_digest=digest(union_contributions_bytes),
        expected_consumer_source_coordinate=coordinate(),
        expected_consumer_source_coordinate_digest=binding.value_digest(coordinate()),
        expected_application_mechanism_digest=app_mechanism,
        expected_compiler_mechanism_digest=compiler_mechanism,
        expected_union_validator_digest=union_mechanism,
        scope_admission_receipt_bytes=None,
        expected_scope_admission_receipt_digest=None,
    )
    inputs = dict(requirements_bytes=cb(requirements), applicability_claim_bytes=cb(claim),
        compiler_manifest_bytes=compiler_bytes, host_selection=host,
        observed_application_mechanism_digest=app_mechanism,
        observed_compiler_mechanism_digest=compiler_mechanism,
        observed_union_validator_digest=union_mechanism)
    return inputs, requirements, claim, profile, union_authority


def assess(inputs):
    return binding.assess_application_authority_binding(**inputs)


def rebind_claim(inputs, claim):
    claim["requirements_digest"] = digest(inputs["requirements_bytes"])
    inputs["applicability_claim_bytes"] = cb(claim)


def test_exact_external_denominator_binds_but_unresolved_authority_and_dependencies_stay_unknown():
    inputs, _, _, _, _ = fixture()
    report = assess(inputs)
    assert report["status"] == "UNKNOWN"
    assert report["binding_status"] == "PASS"
    assert report["authority_status"] == "UNKNOWN"
    assert report["child_status"] == "UNKNOWN"
    assert report["interaction_status"] == "UNKNOWN"
    assert report["polished"] is report["release_authorized"] is False
    assert "QUALIFIED_SCOPE_ADMISSION_RECEIPT_UNAVAILABLE" in report["blockers"]


def test_omitted_member_is_refuted():
    inputs, _, claim, _, _ = fixture()
    claim["member_decisions"].pop()
    inputs["applicability_claim_bytes"] = cb(claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "MEMBER_DECISION_SET_DIFFERS" in report["blockers"]


def test_omitted_instance_is_refuted_even_if_candidate_rebinds_its_claim():
    inputs, requirements, claim, _, _ = fixture()
    removed = requirements["instances"].pop()["instance_id"]
    requirements["tiers"][0]["required_instances"].remove(removed)
    agent = next(row for row in requirements["families"] if row["object_kind"] == "AGENT" and row["tier"] == 1)
    agent["required_instances"].remove(removed)
    inputs["requirements_bytes"] = cb(requirements)
    rebind_claim(inputs, claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "INSTANCE_SET_DIFFERS" in report["blockers"]


def test_duplicate_instance_is_refuted():
    inputs, requirements, claim, _, _ = fixture()
    requirements["instances"].append(deepcopy(requirements["instances"][0]))
    inputs["requirements_bytes"] = cb(requirements)
    rebind_claim(inputs, claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "DUPLICATE_INSTANCE" in report["blockers"]


def test_candidate_cannot_declare_required_member_not_applicable():
    inputs, _, claim, _, _ = fixture()
    claim["member_decisions"][0]["applicability"] = "NOT_APPLICABLE"
    inputs["applicability_claim_bytes"] = cb(claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "MEMBER_APPLICABILITY_DIFFERS" in report["blockers"]


def test_authority_profile_substitution_is_refuted_before_candidate_comparison():
    inputs, _, _, profile, _ = fixture()
    profile["profile_version"] = "substituted"
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": cb(profile)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "HOST_PROFILE_DIGEST_DIFFERS" in report["blockers"]


@pytest.mark.parametrize("field,reason", [
    ("observed_application_mechanism_digest", "APPLICATION_MECHANISM_DIFFERS"),
    ("observed_compiler_mechanism_digest", "COMPILER_MECHANISM_DIFFERS"),
    ("observed_union_validator_digest", "UNION_VALIDATOR_DIFFERS"),
])
def test_installed_mechanism_substitution_is_refuted(field, reason):
    inputs, _, _, _, _ = fixture()
    inputs[field] = ZERO
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert reason in report["blockers"]


def test_consumer_source_coordinate_substitution_is_refuted():
    inputs, _, _, _, _ = fixture()
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "expected_consumer_source_coordinate": {"repository": "foreign"}})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "HOST_SOURCE_COORDINATE_DIGEST_DIFFERS" in report["blockers"]


def test_union_authority_substitution_is_refuted():
    inputs, _, _, _, authority = fixture()
    authority["families"][0]["requirements"].pop()
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "union_authority_bytes": cb(authority)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "UNION_AUTHORITY_DIGEST_DIFFERS" in report["blockers"]


def test_host_selected_union_and_profile_must_name_the_same_members():
    inputs, _, _, profile, authority = fixture()
    authority["families"][0]["requirements"].pop()
    union_bytes = cb(authority)
    profile["union_authority_digest"] = digest(union_bytes)
    profile_bytes = cb(profile)
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": profile_bytes,
           "expected_profile_digest": digest(profile_bytes),
           "union_authority_bytes": union_bytes,
           "expected_union_authority_digest": digest(union_bytes)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "UNION_VALIDATION_FAILED" in report["blockers"]
    assert "UNEXPECTED_MEMBER" in report["union_validation"]["issue_codes"]


def test_compiler_scope_admission_subject_substitution_is_refuted():
    inputs, _, _, profile, _ = fixture()
    compiler = json.loads(inputs["compiler_manifest_bytes"])
    compiler["scope_admission"]["subject"]["operation"] = "OTHER_OPERATION"
    compiler["scope_admission"]["admission_subject_digest"] = binding.value_digest(
        compiler["scope_admission"]["subject"])
    compiler_bytes = cb(compiler)
    profile["compiler_manifest_digest"] = digest(compiler_bytes)
    profile["scope_admission_subject_digest"] = compiler["scope_admission"]["admission_subject_digest"]
    profile_bytes = cb(profile)
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": profile_bytes,
           "expected_profile_digest": digest(profile_bytes)})
    inputs["compiler_manifest_bytes"] = compiler_bytes
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "SCOPE_ADMISSION_SUBJECT_DIFFERS" in report["blockers"]


def test_existing_unordered_instance_lists_remain_semantically_equivalent():
    inputs, requirements, claim, _, _ = fixture()
    requirements["tiers"][0]["required_instances"].reverse()
    agent = next(row for row in requirements["families"] if row["object_kind"] == "AGENT" and row["tier"] == 1)
    agent["required_instances"].reverse()
    requirements["instances"].reverse()
    inputs["requirements_bytes"] = cb(requirements)
    rebind_claim(inputs, claim)
    report = assess(inputs)
    assert report["binding_status"] == "PASS"
    assert report["status"] == "UNKNOWN"


def test_child_failure_dominates_interaction_unknown():
    inputs, _, claim, _, _ = fixture()
    claim["child_outcomes"][0]["status"] = "FAIL"
    claim["child_outcomes"][0]["evidence_digest"] = "sha256:" + "9" * 64
    inputs["applicability_claim_bytes"] = cb(claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert report["child_status"] == "FAIL"
    assert report["interaction_status"] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["child_outcomes", "interaction_outcomes"])
def test_candidate_positive_dependency_status_is_never_accepted(kind):
    inputs, _, claim, _, _ = fixture()
    claim[kind][0]["status"] = "PASS"
    claim[kind][0]["evidence_digest"] = "sha256:" + "9" * 64
    inputs["applicability_claim_bytes"] = cb(claim)
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "UNQUALIFIED_DEPENDENCY_PASS" in report["blockers"]


def test_host_selected_not_applicable_requires_qualified_receipt_and_stays_unknown():
    inputs, _, _, _, _ = fixture(not_applicable=True)
    report = assess(inputs)
    assert report["status"] == "UNKNOWN"
    assert report["binding_status"] == "PASS"
    assert report["authority_status"] == "UNKNOWN"
    assert "QUALIFIED_SCOPE_ADMISSION_RECEIPT_UNAVAILABLE" in report["blockers"]


def test_not_applicable_without_host_selected_basis_is_refuted():
    inputs, _, _, profile, _ = fixture(not_applicable=True)
    profile["member_requirements"][1]["inapplicability_basis_digest"] = None
    profile_bytes = cb(profile)
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": profile_bytes,
           "expected_profile_digest": digest(profile_bytes)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "INAPPLICABILITY_BASIS_REQUIRED" in report["blockers"]


def test_family_not_applicable_without_host_selected_basis_is_refuted():
    inputs, _, _, profile, _ = fixture()
    row = next(item for item in profile["family_requirements"]
               if item["object_kind"] == "TOKEN" and item["tier"] == 9)
    row["applicability"] = "NOT_APPLICABLE"
    profile["receipt_mode"] = "QUALIFIED_SCOPE_ADMISSION_REQUIRED"
    profile_bytes = cb(profile)
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": profile_bytes,
           "expected_profile_digest": digest(profile_bytes)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "INAPPLICABILITY_BASIS_REQUIRED" in report["blockers"]


def test_duplicate_expected_member_is_refuted():
    inputs, _, _, profile, _ = fixture()
    profile["member_requirements"].append(deepcopy(profile["member_requirements"][0]))
    profile_bytes = cb(profile)
    host = inputs["host_selection"]
    inputs["host_selection"] = binding.ApplicationAuthorityHostSelection(
        **{**host.__dict__, "profile_bytes": profile_bytes,
           "expected_profile_digest": digest(profile_bytes)})
    report = assess(inputs)
    assert report["status"] == "FAIL"
    assert "DUPLICATE_EXPECTED_MEMBER" in report["blockers"]
