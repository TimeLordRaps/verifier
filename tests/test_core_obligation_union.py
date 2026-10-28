"""Tiny synthetic tests for the private core obligation union validator.

JavaScript Object Notation (JSON) supplies the candidate source encoding.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from verifier.runtime import core_obligation_union as validator


def h(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def coordinate() -> dict:
    return {
        "repository": "verifier-standard",
        "branch": "reconcile/synthetic",
        "head_commit": "a" * 40,
        "dirty_state_digest": h(b"synthetic dirty state"),
        "source_artifacts": [
            {"path": "src/verifier/domains/contracts/application_requirements.py",
             "sha256": h(b"synthetic requirements source")},
            {"path": "src/verifier/domains/inventory.py",
             "sha256": h(b"synthetic census source")},
        ],
    }


def source(name: str) -> dict:
    return {"uri": f"standard://{name}", "sha256": h(name.encode("utf-8"))}


def required(object_kind: str, tier: int, member_id: str, claim: str) -> dict:
    return {
        "object_kind": object_kind,
        "tier": tier,
        "member_id": member_id,
        "source": source(member_id),
        "claim_sha256": h(claim.encode("utf-8")),
    }


def row(requirement: dict, claim: str) -> dict:
    return {
        "source": deepcopy(requirement["source"]),
        "claim": {"text": claim, "sha256": h(claim.encode("utf-8"))},
        "object_kind": requirement["object_kind"],
        "tier": requirement["tier"],
        "member_id": requirement["member_id"],
        "acceptance_mechanism": {"kind": "UNKNOWN", "identifier": None},
        "current_evidence": {"status": "UNKNOWN", "bindings": []},
        "uncovered_action": "Obtain independently source-derived authority and evidence.",
    }


def fixture() -> tuple[dict, list[dict], dict]:
    coord = coordinate()
    producer_data = "sha256:" + "1" * 64
    producer_graph = "sha256:" + "2" * 64
    data_claim = "Bind the exact retained DATA member."
    graph_claim = "Bind the exact retained GRAPH member."
    graph_second_claim = "Replay the second GRAPH member."
    data = required("DATA", 1, "DATA-1.1", data_claim)
    graph = required("GRAPH", 2, "GRAPH-2.1", graph_claim)
    graph_second = required("GRAPH", 2, "GRAPH-2.2", graph_second_claim)
    data_dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": validator.value_digest(producer_data),
        "consumer_source_coordinate_digest": validator.value_digest(coord),
        "candidate_input_digest": h(b"data candidate"),
        "package_digest": h(b"data package"),
        "mechanism_digest": h(b"data mechanism"),
    }
    graph_dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": validator.value_digest(producer_graph),
        "consumer_source_coordinate_digest": validator.value_digest(coord),
        "candidate_input_digest": h(b"graph candidate"),
        "package_digest": h(b"graph package"),
        "mechanism_digest": h(b"graph mechanism"),
    }
    authority = {
        "schema_version": validator.AUTHORITY_SCHEMA,
        "candidate_status": "CANDIDATE",
        "completeness": "UNKNOWN",
        "consumer_source_coordinate": coord,
        "families": [
            {"family_id": "domain-data", "source_map_digest": h(b"data map"),
             "producer_source_coordinate": producer_data,
             "dependency_selection": data_dependency,
             "requirements": [data]},
            {"family_id": "graph-axis", "source_map_digest": h(b"graph map"),
             "producer_source_coordinate": producer_graph,
             "dependency_selection": graph_dependency,
             "requirements": [graph, graph_second]},
        ],
    }
    contributions = [
        {"schema_version": validator.CONTRIBUTION_SCHEMA,
         "candidate_status": "CANDIDATE", "completeness": "UNKNOWN",
         "producer_source_coordinate": producer_data,
         "consumer_source_coordinate": deepcopy(coord), "family_id": "domain-data",
         "source_map_digest": h(b"data map"), "dependency_binding": deepcopy(data_dependency),
         "rows": [row(data, data_claim)]},
        {"schema_version": validator.CONTRIBUTION_SCHEMA,
         "candidate_status": "CANDIDATE", "completeness": "UNKNOWN",
         "producer_source_coordinate": producer_graph,
         "consumer_source_coordinate": deepcopy(coord), "family_id": "graph-axis",
         "source_map_digest": h(b"graph map"), "dependency_binding": deepcopy(graph_dependency),
         "rows": [row(graph, graph_claim), row(graph_second, graph_second_claim)]},
    ]
    return authority, contributions, coord


def issue_codes(report: dict) -> set[str]:
    return {issue["code"] for issue in report["issues"]}


def validate(authority: dict, contributions: list[dict], coord: dict) -> dict:
    return validator.validate_union(
        authority,
        contributions,
        expected_authority_digest=validator.value_digest(authority),
        expected_source_coordinate=coord,
    )


def test_structurally_complete_candidate_stays_semantically_unknown():
    authority, contributions, coord = fixture()
    report = validate(authority, contributions, coord)

    assert report["structural_union"] == "PASS"
    assert report["candidate_coverage"] == "MATCHED"
    assert report["authority_binding"] == "MATCHED"
    assert report["source_coordinate_binding"] == "MATCHED"
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_admissible"] is False
    assert report["issues"] == []


def test_omitted_family_tier_and_member_are_each_visible():
    authority, contributions, coord = fixture()
    contributions.pop()
    report = validate(authority, contributions, coord)

    assert report["structural_union"] == "FAIL"
    assert {"MISSING_FAMILY", "MISSING_TIER", "MISSING_MEMBER"} <= issue_codes(report)
    assert report["semantic_completeness"] == "UNKNOWN"


def test_member_omission_inside_present_tier_is_detected_without_inventing_a_new_family():
    authority, contributions, coord = fixture()
    contributions[1]["rows"].pop()
    report = validate(authority, contributions, coord)

    assert "MISSING_MEMBER" in issue_codes(report)
    assert "MISSING_FAMILY" not in issue_codes(report)
    assert "MISSING_TIER" not in issue_codes(report)


def test_duplicate_family_and_cross_family_member_ownership_are_rejected():
    authority, contributions, coord = fixture()
    duplicate_family = deepcopy(contributions[0])
    cross_family = deepcopy(contributions[0]["rows"][0])
    cross_family["source"] = deepcopy(authority["families"][1]["requirements"][0]["source"])
    cross_family["claim"] = {"text": "Bind the exact retained GRAPH member.",
                             "sha256": authority["families"][1]["requirements"][0]["claim_sha256"]}
    cross_family["object_kind"] = "GRAPH"
    cross_family["tier"] = 2
    cross_family["member_id"] = "GRAPH-2.1"
    contributions[0]["rows"].append(cross_family)
    contributions.append(duplicate_family)
    report = validate(authority, contributions, coord)

    assert {"DUPLICATE_FAMILY", "DUPLICATE_MEMBER"} <= issue_codes(report)


def test_foreign_coordinate_and_mismatched_source_evidence_bindings_are_rejected():
    authority, contributions, coord = fixture()
    contribution = contributions[0]
    contribution["consumer_source_coordinate"]["head_commit"] = "b" * 40
    item = contribution["rows"][0]
    item["source"]["sha256"] = h(b"neighbor source")
    item["current_evidence"] = {
        "status": "AVAILABLE",
        "bindings": [{
            "evidence_id": "evidence-1",
            "uri": "evidence://synthetic/1",
            "sha256": h(b"synthetic evidence"),
            "producer_source_coordinate_digest": h(b"foreign producer coordinate"),
            "consumer_source_coordinate_digest": h(b"foreign consumer coordinate"),
            "source_sha256": h(b"other source"),
            "claim_sha256": h(b"other claim"),
            "object_kind": "MODEL",
            "tier": 9,
            "member_id": "MODEL-9.9",
        }],
    }
    report = validate(authority, contributions, coord)

    assert {"FOREIGN_SOURCE_COORDINATE", "SOURCE_BINDING_MISMATCH",
            "EVIDENCE_BINDING_MISMATCH"} <= issue_codes(report)


def test_complete_or_pass_assertions_are_unsupported_even_when_rows_match():
    authority, contributions, coord = fixture()
    authority["completeness"] = "COMPLETE"
    contributions[0]["candidate_status"] = "PASS"
    contributions[1]["completeness"] = "COMPLETE"
    report = validator.validate_union(
        authority,
        contributions,
        expected_authority_digest=validator.value_digest(authority),
        expected_source_coordinate=coord,
    )

    assert {"UNSUPPORTED_COMPLETENESS_ASSERTION", "UNSUPPORTED_CANDIDATE_STATUS"} <= issue_codes(report)
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_admissible"] is False


def test_harness_candidate_adapter_preserves_distinct_coordinates_and_grants_no_authority():
    coord = coordinate()
    producer = "sha256:" + "9" * 64
    source_sha = sha256(b"README source").hexdigest()
    candidate = {
        "schema_version": "times-harness-private-nine-core-census-candidate-1",
        "source_coordinate": producer,
        "candidate_member_count": 1,
        "claim_sources": {"README.md": {"sha256": source_sha}},
        "members": [{
            "member_id": "surface-declaration",
            "claim": "A session freezes its declared surface.",
            "claim_source": "README.md#surface",
            "object": {"kind": "HARNESS", "tier": 1, "tier_name": "FACETS"},
            "member_identity": {"source": "src/times_harness/recorder.py", "symbol": "Session"},
            "acceptance_mechanism": {"test": "tests/test_surface.py", "node": "test_surface",
                                     "predicate": "Synthetic candidate predicate."},
            "current_evidence": {"implementation": "IMPLEMENTED", "evidence": "SYNTHETIC_TESTED"},
            "uncovered_action": "Obtain independent recorder evidence.",
        }],
        "completeness": {"status": "NOT_ESTABLISHED"},
    }
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode("utf-8")

    contribution = validator.adapt_harness_candidate(
        raw,
        consumer_source_coordinate=coord,
        expected_package_digest=None,
        expected_mechanism_digest=None,
    )

    assert contribution["producer_source_coordinate"] == producer
    assert contribution["consumer_source_coordinate"] == coord
    assert contribution["candidate_status"] == "CANDIDATE"
    assert contribution["completeness"] == "UNKNOWN"
    assert contribution["dependency_binding"]["status"] == "UNKNOWN"
    assert contribution["dependency_binding"]["package_digest"] is None
    assert contribution["dependency_binding"]["mechanism_digest"] is None
    assert contribution["rows"][0]["current_evidence"]["status"] == "UNKNOWN"
    report = validator.validate_union(
        None,
        [contribution],
        expected_authority_digest=None,
        expected_source_coordinate=coord,
    )
    assert "AUTHORITY_REQUIRED" in issue_codes(report)
    assert "DEPENDENCY_SELECTION_INCOMPLETE" in issue_codes(report)
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_admissible"] is False


def release_ledger() -> dict:
    source_path = "src/verifier/standard/CURRENT_ARCH_SHAPES.md"
    source_sha = sha256(b"ARCH shapes source").hexdigest()
    return {
        "schema_version": "verifier-v2-core-release-evidence-ledger-1",
        "source_coordinate": {
            "root": "urn:verifier:test-source:release-ledger",
            "branch_from_git_metadata": "qualification/synthetic",
            "head_from_git_metadata": "b" * 40,
            "dirty_state": "UNKNOWN_NOT_REVALIDATED",
            "source_writes": 0,
        },
        "release_boundary": {
            "time_status": "OPEN",
            "release_clearance": "BLOCKED",
        },
        "selection": {"selected_slice": ["ARCH"]},
        "inventory": {
            "registered_member_row_count": 1,
            "candidate_member_set_authenticates_completeness": False,
        },
        "rows": [{
            "row_id": "verifier-current-object-obligations-1:ARCH-3.1",
            "source_claim": {
                "exact_claim": "The retained ARCH graph satisfies its declared shape equations.",
                "normative_sources": [{"path": source_path, "role": "bounded member contract"}],
                "claim_status": "REGISTERED_BOUNDED_PROPOSITION",
            },
            "object_tier": {"object": "ARCH", "tier": 3, "tier_name": "STATICS"},
            "member_identity": {"coordinate": "ARCH-3.1"},
            "acceptance_mechanism": {
                "checker_symbol": "verifier.domains.contracts.arch_shapes.recheck",
                "public_route_and_tests": "tests/test_arch.py::test_public_route",
            },
            "current_evidence": {
                "registration_observed_in_source": True,
                "checker_symbol_resolves": True,
                "named_test_symbol_present": True,
                "named_test_executed_for_this_contribution": False,
                "checker_executed_for_this_contribution": False,
                "runtime_verified": False,
                "evidence_credit": "NONE",
            },
            "uncovered_action": {
                "member_evidence": "Run an independently selected certificate.",
                "family_closure": "Establish required-member closure independently.",
            },
        }],
        "source_bindings": {source_path: {"sha256": source_sha, "exists": True}},
        "gap_summary": {
            "runtime_verified_members": 0,
            "retained_certificate_members": 0,
            "selected_slots_with_established_objective_inventory_closure": 0,
        },
    }


def test_release_ledger_adapter_splits_only_selected_families_and_grants_no_runtime_credit():
    coord = coordinate()
    ledger = release_ledger()
    raw = json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode("utf-8")

    contributions = validator.adapt_release_evidence_ledger(
        raw,
        consumer_source_coordinate=coord,
        expected_package_digest=None,
        expected_mechanism_digest=None,
    )

    assert len(contributions) == 1
    contribution = contributions[0]
    assert contribution["family_id"] == "VERIFIER_CURRENT_OBJECT:ARCH"
    assert contribution["producer_source_coordinate"] == ledger["source_coordinate"]
    assert contribution["consumer_source_coordinate"] == coord
    assert contribution["rows"][0]["current_evidence"]["status"] == "UNKNOWN"
    assert contribution["rows"][0]["current_evidence"]["reported"]["runtime_verified"] is False
    report = validator.validate_union(
        None,
        contributions,
        expected_authority_digest=None,
        expected_source_coordinate=coord,
    )
    assert {"AUTHORITY_REQUIRED", "DEPENDENCY_SELECTION_INCOMPLETE"} <= issue_codes(report)
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_admissible"] is False


def test_release_ledger_adapter_rejects_internal_member_omission_and_source_mismatch():
    coord = coordinate()
    ledger = release_ledger()
    ledger["inventory"]["registered_member_row_count"] = 2
    raw = json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ValueError, match="row count"):
        validator.adapt_release_evidence_ledger(
            raw,
            consumer_source_coordinate=coord,
            expected_package_digest=None,
            expected_mechanism_digest=None,
        )

    ledger = release_ledger()
    source_path = next(iter(ledger["source_bindings"]))
    ledger["source_bindings"][source_path]["exists"] = False
    raw = json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ValueError, match="source binding"):
        validator.adapt_release_evidence_ledger(
            raw,
            consumer_source_coordinate=coord,
            expected_package_digest=None,
            expected_mechanism_digest=None,
        )


@pytest.mark.parametrize("ambiguous_prefix", [
    b'{"schema_version":"forged-duplicate",',
    b'{"non_finite_extension":NaN,',
])
def test_release_ledger_adapter_rejects_ambiguous_json(ambiguous_prefix):
    coord = coordinate()
    raw = json.dumps(release_ledger(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ambiguous = ambiguous_prefix + raw[1:]

    with pytest.raises(ValueError, match="JSON unavailable"):
        validator.adapt_release_evidence_ledger(
            ambiguous,
            consumer_source_coordinate=coord,
            expected_package_digest=None,
            expected_mechanism_digest=None,
        )


def core_family_slice() -> dict:
    rows = []
    for tier in range(1, 10):
        member = f"ACTOR-{tier}.1"
        path = f"src/verifier/standard/ACTOR_{tier}.md"
        rows.append({
            "exact_object_and_tier": {"object": "ACTOR", "tier": tier},
            "members": [{
                "identity": {"coordinate": member},
                "source_claim": {
                    "exact_claim": f"Bounded ACTOR tier {tier} proposition.",
                    "normative_sources_named_by_checker": [{
                        "path": path,
                        "sha256": sha256(path.encode()).hexdigest(),
                    }],
                },
                "acceptance_mechanism": {"recheck_function": f"verifier.actor.recheck_{tier}"},
                "current_evidence": {"certificate_instance_replay_in_this_review": "UNRUN"},
            }],
            "current_evidence": {"objective_inventory_closure": "NOT_ESTABLISHED"},
            "uncovered_action": {
                "action": "Authenticate the applicable member set and run retained evidence.",
                "candidate_boundary": "Candidate rows are not an exhaustive list.",
            },
        })
    return {
        "record_type": "v2_core_family_slice_read_only_review",
        "status": "ACTIVE_GAPS_FOUND_STATIC_EVIDENCE_ONLY",
        "partition": {"selected_slice": [{"index": 0, "object": "ACTOR"}]},
        "rows": rows,
        "source_observations": {
            "repository": "urn:verifier:test-source:family-slice",
            "git_coordinate": {"branch": "reconcile/synthetic", "head": "c" * 40,
                               "git_status_sha256_lf": sha256(b"dirty").hexdigest()},
            "time_status": "OPEN",
        },
        "counterexample": {"registered_member_identities": 9},
        "claim_limits": ["No completeness is established."],
    }


def test_core_family_slice_adapter_retains_static_only_status_and_distinct_coordinates():
    coord = coordinate()
    candidate = core_family_slice()
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()

    contributions = validator.adapt_core_family_slice(
        raw,
        consumer_source_coordinate=coord,
        expected_package_digest=None,
        expected_mechanism_digest=None,
    )

    assert len(contributions) == 1
    assert contributions[0]["family_id"] == "VERIFIER_CURRENT_OBJECT:ACTOR"
    assert contributions[0]["producer_source_coordinate"] != coord
    assert len(contributions[0]["rows"]) == 9
    assert all(row["current_evidence"]["status"] == "UNKNOWN"
               for row in contributions[0]["rows"])
    report = validator.validate_union(
        None,
        contributions,
        expected_authority_digest=None,
        expected_source_coordinate=coord,
    )
    assert {"AUTHORITY_REQUIRED", "DEPENDENCY_SELECTION_INCOMPLETE"} <= issue_codes(report)
    assert report["release_admissible"] is False


def test_core_family_slice_adapter_rejects_omitted_selected_tier():
    coord = coordinate()
    candidate = core_family_slice()
    candidate["rows"].pop()
    candidate["counterexample"]["registered_member_identities"] = 8
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="tier coverage"):
        validator.adapt_core_family_slice(
            raw,
            consumer_source_coordinate=coord,
            expected_package_digest=None,
            expected_mechanism_digest=None,
        )


def selected_family_matrix() -> dict:
    source_hashes = {}
    rows = []
    for tier in range(1, 10):
        path = f"src/verifier/standard/AGENT_{tier}.md"
        source_hashes[path] = sha256(path.encode()).hexdigest()
        rows.append({
            "object_kind": "AGENT",
            "tier": tier,
            "source_files": [path],
            "claim": f"Bounded AGENT tier {tier} proposition.",
            "member_identities": [{
                "objective": f"AGENT-{tier}.1",
                "certificate_schema_version": f"agent-{tier}-certificate-1",
                "proposition_digest": h(f"prop-{tier}".encode()),
                "object_profile_conformance": "NOT_ESTABLISHED",
            }],
            "acceptance_mechanism": "Registered route replay with independent selection.",
            "current_evidence": "UNKNOWN/UNRUN; whole-tier conformance is NOT_ESTABLISHED.",
            "uncovered_action": "Authenticate expected members and replay exact evidence.",
        })
    return {
        "schema": "verifier-v2-selected-family-obligation-matrix-1",
        "generated_from": {
            "source_root": "urn:verifier:test-source:family-matrix",
            "head": "d" * 40,
            "dirty": True,
            "git_status_short_sha256": sha256(b"dirty-two").hexdigest(),
            "source_file_sha256": source_hashes,
        },
        "owned_object_kinds": ["AGENT"],
        "rows": rows,
    }


def test_selected_family_matrix_adapter_preserves_unknown_instance_status():
    coord = coordinate()
    matrix = selected_family_matrix()
    raw = json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()
    contributions = validator.adapt_selected_family_matrix(
        raw,
        consumer_source_coordinate=coord,
        expected_package_digest=None,
        expected_mechanism_digest=None,
    )
    assert [item["family_id"] for item in contributions] == ["VERIFIER_CURRENT_OBJECT:AGENT"]
    assert len(contributions[0]["rows"]) == 9
    assert all(item["current_evidence"]["status"] == "UNKNOWN"
               for item in contributions[0]["rows"])
    report = validator.validate_union(
        None, contributions, expected_authority_digest=None, expected_source_coordinate=coord)
    assert {"AUTHORITY_REQUIRED", "DEPENDENCY_SELECTION_INCOMPLETE"} <= issue_codes(report)
    assert report["release_admissible"] is False


def test_selected_family_matrix_adapter_rejects_duplicated_member_identity():
    coord = coordinate()
    matrix = selected_family_matrix()
    matrix["rows"][1]["member_identities"][0]["objective"] = "AGENT-1.1"
    matrix["rows"][1]["tier"] = 1
    raw = json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="duplicate"):
        validator.adapt_selected_family_matrix(
            raw,
            consumer_source_coordinate=coord,
            expected_package_digest=None,
            expected_mechanism_digest=None,
        )


def interaction_map() -> dict:
    kinds = ["DATA", "RECEIPT", "GRAPH"]
    slot_rows = []
    members = []
    candidate_by_kind = {}
    files = []
    for kind in kinds:
        candidate_by_kind[kind] = 1
        path = f"src/verifier/standard/CURRENT_{kind}.md"
        digest = sha256(path.encode()).hexdigest()
        files.append({"path": path, "sha256": digest, "exists": True,
                      "matches_retained_source_coordinate": True})
        for tier in range(1, 10):
            slot_rows.append({
                "object_kind": kind,
                "tier": tier,
                "full_family_closure": "UNKNOWN",
                "full_family_members": None,
                "registered_candidate_members": [f"{kind}-{tier}.1"] if tier == 1 else [],
            })
        members.append({
            "object_kind": kind,
            "tier": 1,
            "member_identity": {"coordinate": f"{kind}-1.1",
                                "proposition_digest": h(f"{kind}-prop".encode())},
            "membership_status": "REGISTERED_CANDIDATE; FULL_APPLICATION_APPLICABILITY_AND_FAMILY_CLOSURE_UNKNOWN",
            "source_claim": {
                "exact_claim": f"Bounded {kind} proposition.",
                "specification": {"path": path, "sha256": digest, "exists": True},
            },
            "acceptance_mechanism": {"checker": f"verifier.{kind.lower()}.recheck"},
            "current_evidence": {"objective_inventory_closure": "NOT_ESTABLISHED",
                                 "certificate_replay_for_actual_application": "NOT_SUPPLIED"},
            "uncovered_action": "Select applicability and replay the exact certificate.",
        })
    return {
        "schema_version": "reviewer-b-core-obligation-interaction-map-1",
        "status": "SOURCE_BOUND_MAP_COMPLETE; FULL_APPLICATION_AND_RELEASE_ADMISSION_UNKNOWN",
        "claim_boundary": {"candidate_registry_completeness": "NOT_AUTHENTICATED",
                           "full_current_application": "UNKNOWN"},
        "counts": {"slot_rows": 27, "registered_candidate_member_rows": 3,
                   "candidate_by_kind": candidate_by_kind,
                   "actual_instantiated_source_requirements": 0},
        "slot_rows": slot_rows,
        "registered_candidate_member_rows": members,
        "source_binding": {"retained_source_coordinate": h(b"retained-source"),
                           "source_root": "urn:verifier:test-source:interaction-map"},
        "source_snapshot": {"manifest_digest": h(b"snapshot"), "files": files},
    }


def test_interaction_map_adapter_retains_uninstantiated_unknown_boundary():
    coord = coordinate()
    candidate = interaction_map()
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    contributions = validator.adapt_interaction_map(
        raw, consumer_source_coordinate=coord,
        expected_package_digest=None, expected_mechanism_digest=None)
    assert [item["family_id"] for item in contributions] == [
        "VERIFIER_CURRENT_OBJECT:DATA", "VERIFIER_CURRENT_OBJECT:RECEIPT",
        "VERIFIER_CURRENT_OBJECT:GRAPH"]
    assert sum(len(item["rows"]) for item in contributions) == 3
    assert all(row["current_evidence"]["status"] == "UNKNOWN"
               for item in contributions for row in item["rows"])
    report = validator.validate_union(
        None, contributions, expected_authority_digest=None, expected_source_coordinate=coord)
    assert {"AUTHORITY_REQUIRED", "DEPENDENCY_SELECTION_INCOMPLETE"} <= issue_codes(report)
    assert report["release_admissible"] is False


def test_interaction_map_adapter_rejects_claimed_closure_and_missing_tier():
    coord = coordinate()
    candidate = interaction_map()
    candidate["slot_rows"][0]["full_family_closure"] = "PASS"
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="closure"):
        validator.adapt_interaction_map(
            raw, consumer_source_coordinate=coord,
            expected_package_digest=None, expected_mechanism_digest=None)
    candidate = interaction_map()
    candidate["slot_rows"].pop()
    candidate["counts"]["slot_rows"] = 26
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="tier coverage"):
        validator.adapt_interaction_map(
            raw, consumer_source_coordinate=coord,
            expected_package_digest=None, expected_mechanism_digest=None)


def model_train_bundle() -> tuple[bytes, bytes, bytes, bytes]:
    census_rows = []
    for kind in ["MODEL", "TRAIN"]:
        for tier in range(1, 10):
            census_rows.append({
                "exact_object_tier": {"kind": kind, "tier": tier},
                "member_identity": {"candidate_member_id": f"core:{kind}:tier:{tier}"},
                "current_evidence": {"tier_closure": "NOT_ESTABLISHED"},
            })
    census = {
        "schema_version": "private-verifier-core-v2-model-train-tier-census-1",
        "scope": ["MODEL", "TRAIN"], "row_count": 18, "rows": census_rows,
        "candidate_completeness_claim": "NONE",
        "normative_inventory_completeness": "NOT_ESTABLISHED",
        "required_subject_instance_denominator": "UNKNOWN",
    }
    legacy = []
    current = []
    for kind in ["MODEL", "TRAIN"]:
        path = f"src/verifier/standard/{kind}.md"
        digest = sha256(path.encode()).hexdigest()
        for tier in range(1, 10):
            legacy.append({
                "exact_object_tier": {"kind": kind, "tier": tier,
                                      "semantic_family": "legacy-domain-catalogue"},
                "member_identity": {"coordinate": f"{kind}-{tier}.1",
                                    "semantic_family": "legacy-domain-catalogue"},
                "source_claim": {"claim": f"Legacy {kind} tier {tier} obligation.",
                                 "source": {"path": path, "sha256": digest}},
                "acceptance_mechanism": "Independent legacy receipt.",
                "current_evidence": {"closure": "NOT_ESTABLISHED"},
                "uncovered_action": "Obtain an independent original-obligation receipt.",
            })
            current.append({
                "exact_object_tier": {"kind": kind, "tier": tier,
                                      "semantic_version": "verifier-current-object-obligations-1"},
                "member_identity": {"coordinate": f"{kind}-{tier}.1",
                                    "certificate_schema_version": f"{kind.lower()}-{tier}-certificate-1"},
                "source_claim": {"claim": f"Current {kind} tier {tier} objective.",
                                 "source": {"path": path, "sha256": digest}},
                "acceptance_mechanism": ["Exact current replay."],
                "current_evidence": {"instance_status": "UNESTABLISHED",
                                     "whole_kind_tier_closure": "NOT_ESTABLISHED"},
                "uncovered_action": ["Select the required instance."],
            })
    reconciliation = {
        "schema_version": "private-verifier-core-v2-model-train-obligation-reconciliation-1",
        "coordinate_reuse_rule": "Legacy and current coordinate spellings are not aliases; semantic family/version is mandatory.",
        "legacy_original_obligation_count": len(legacy), "legacy_original_obligations": legacy,
        "registered_current_objective_count": len(current), "registered_current_objectives": current,
    }
    public = {
        "schema_version": "private-verifier-core-v2-public-release-obligations-1",
        "overall": "NOT_READY", "row_count": 1,
        "rows": [{"release_obligation_id": "R01", "uncovered_action": "Bind release artifacts."}],
    }
    raw = {
        "CENSUS.json": json.dumps(census, sort_keys=True, separators=(",", ":")).encode(),
        "RECONCILIATION.json": json.dumps(reconciliation, sort_keys=True, separators=(",", ":")).encode(),
        "PUBLIC-RELEASE-OBLIGATIONS.json": json.dumps(public, sort_keys=True, separators=(",", ":")).encode(),
    }
    sealed = {
        "schema_version": "private-verifier-core-v2-census-sealed-manifest-1",
        "outcome": "NOT_READY", "source_head": "e" * 40,
        "source_coordinate": "pinned synthetic source",
        "member_count": 3,
        "members": [{"path": name, "sha256": sha256(data).hexdigest(), "bytes": len(data)}
                    for name, data in raw.items()],
    }
    sealed_raw = json.dumps(sealed, sort_keys=True, separators=(",", ":")).encode()
    return raw["CENSUS.json"], raw["RECONCILIATION.json"], raw["PUBLIC-RELEASE-OBLIGATIONS.json"], sealed_raw


def test_model_train_adapter_keeps_reused_coordinates_in_distinct_semantic_families():
    coord = coordinate()
    census, reconciliation, public, sealed = model_train_bundle()
    result = validator.adapt_model_train_bundle(
        census, reconciliation, public, sealed,
        consumer_source_coordinate=coord,
        expected_package_digest=None, expected_mechanism_digest=None)
    assert len(result["contributions"]) == 2
    ids = [row["member_id"] for item in result["contributions"] for row in item["rows"]]
    assert "legacy-domain-catalogue::MODEL-1.1" in ids
    assert "verifier-current-object-obligations-1::MODEL-1.1" in ids
    assert len(ids) == len(set(ids)) == 36
    assert result["release_obligations"]["overall"] == "NOT_READY"
    report = validator.validate_union(
        None, result["contributions"], expected_authority_digest=None,
        expected_source_coordinate=coord)
    assert {"AUTHORITY_REQUIRED", "DEPENDENCY_SELECTION_INCOMPLETE"} <= issue_codes(report)
    assert report["release_admissible"] is False


def test_model_train_adapter_rejects_manifest_mismatch_and_semantic_family_collapse():
    coord = coordinate()
    census, reconciliation, public, sealed = model_train_bundle()
    changed = bytearray(census)
    changed[-2] = ord(" ")
    with pytest.raises(ValueError, match="manifest"):
        validator.adapt_model_train_bundle(
            bytes(changed), reconciliation, public, sealed,
            consumer_source_coordinate=coord,
            expected_package_digest=None, expected_mechanism_digest=None)
    rec = json.loads(reconciliation)
    rec["coordinate_reuse_rule"] = "Coordinates are aliases."
    reconciliation = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    sealed_doc = json.loads(sealed)
    for item in sealed_doc["members"]:
        if item["path"] == "RECONCILIATION.json":
            item["sha256"] = sha256(reconciliation).hexdigest()
            item["bytes"] = len(reconciliation)
    sealed = json.dumps(sealed_doc, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="nonaliases"):
        validator.adapt_model_train_bundle(
            census, reconciliation, public, sealed,
            consumer_source_coordinate=coord,
            expected_package_digest=None, expected_mechanism_digest=None)
