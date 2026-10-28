"""Prepared native replay extension registry tests."""
from __future__ import annotations

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_extensions as extensions
from verifier.runtime import self_polish_native_tier3_cases as tier3


def test_prepared_extension_registry_is_exact_and_not_installed() -> None:
    registry = extensions.prepared_extension_registry()

    assert registry["status"] == "PREPARED_NOT_INSTALLED"
    assert registry["tiers"] == [3, 4, 5, 6, 7, 8, 9]
    assert registry["tier_membership_counts"] == {
        "3": 31, "4": 32, "5": 26, "6": 26, "7": 156,
        "8": 26, "9": 29,
    }
    assert registry["membership_count"] == 326
    assert registry["case_count"] == 978
    assert registry["builder_adapter_counts"] == {
        "BOUNDED_EVIDENCE_BYTES": 323,
        "HYPER_OBJECT_COLLECTION": 1,
        "SIM_OBJECT_GROUNDING": 1,
        "WINDOWS_MODEL_HARDWARE_OBSERVATION": 1,
    }
    assert registry["negative_adapter_counts"] == {
        "GOVERNANCE_INVALID_SIGNATURE": 26,
        "GRAPH_EDGE_CONTENT_SUBSTITUTION": 1,
        "HYPER_UNRELATED_OBJECT_COLLECTION": 1,
        "MALFORMED_EVIDENCE_REBIND": 269,
        "RECEIPT_ATTESTATION_SIGNATURE_BIT_FLIP": 1,
        "RECEIPT_CHAIN_ENTRY_SUBSTITUTION": 1,
        "SIM_ISOLATION_MALFORMED_REBIND": 1,
        "SUBJECT_SECURITY_VALID_TRANSPLANT": 26,
    }
    assert registry["unknown_adapter_counts"] == {
        "ABSENT_EVIDENCE": 325,
        "HYPER_CLOSURE_OPERATION_BUDGET": 1,
    }
    assert registry["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert registry["release_authority"] == "NONE"
    body = {key: value for key, value in registry.items()
            if key != "registry_digest"}
    assert registry["registry_digest"] \
        == core_obligation_union.value_digest(body)


def test_prepared_extension_inputs_match_registry_memberships() -> None:
    registry = extensions.prepared_extension_registry()
    selected = extensions.prepared_extension_case_inputs()
    memberships = {
        row["obligation_id"]: row
        for rows in registry["memberships_by_tier"].values()
        for row in rows
    }

    assert len(selected) == 326
    assert set(selected) == set(memberships)
    for identifier, case in selected.items():
        row = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == row["checking_mechanism"]
        assert request["coordinate"] == row["coordinate"]
        assert request["semantic_version"] == row["semantic_version"]
        assert request["proposition_digest"] == row["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])


def test_installed_graph_repin_does_not_promote_extension_release_status() -> None:
    registry = extensions.prepared_extension_registry()
    review = tier3.installed_source_review()["GRAPH:GRAPH-3.1"]
    installed = tier3.installed_case_inputs()["GRAPH:GRAPH-3.1"]
    prepared = extensions.prepared_extension_case_inputs()["GRAPH:GRAPH-3.1"]

    assert registry["status"] == "PREPARED_NOT_INSTALLED"
    assert registry["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert registry["release_authority"] == "NONE"
    assert review["disposition"] == "ACCEPT_REPIN"
    assert installed["policy"]["mechanism_digest"] == review["reviewed_mechanism_digest"]
    assert installed["policy"]["mechanism_digest"] != review["prior_mechanism_digest"]
    assert prepared == installed
